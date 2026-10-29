//! Owned HTTP fixtures exercise the production official-client boundary; no
//! GitHub request, source execution, release, or commit status is made here.
use base64::Engine;
use leap_release_launcher::{
    Environment,
    ci_request::{CI_STAGES, SourceCiRequest},
    source_api::{GitHubApi, Role, SourceApi},
    source_discovery::{
        Approval, acquire_approval, correlation_id, discover_cli, fresh_source, select_candidates,
    },
    source_handoff::{cleanup_candidates, retain_stage_with, verify_stage_receipt},
    source_report::{report_cli, source_status},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

fn sha(value: &Value) -> String {
    format!("{:x}", Sha256::digest(serde_json::to_vec(value).unwrap()))
}
fn identity() -> Value {
    json!({"source_repository":"example-org/private-source","source_sha":"a".repeat(40),"builder_repository":"omnisolo-llc/leapterm-release","builder_sha":"b".repeat(40),"run_id":"123","attempt":"1"})
}
fn request(stage: &str) -> SourceCiRequest {
    SourceCiRequest::parse(&json!({"identity":identity(),"source_ref":"refs/heads/main","stage":stage,"shard_index":0,"shard_count":1})).unwrap()
}
fn receipt(stage: &str) -> Value {
    let id = format!("{stage}:gate:0000");
    let cases = json!([format!("{id}::registered-case")]);
    json!({"schema":"leapterm.source-ci.stage.v1","request":request(stage),"catalog_sha256":"c".repeat(64),"inputs":{"Cargo.toml":"d".repeat(64)},"suites":[{"id":id,"kind":"rust","command_sha256":"e".repeat(64),"input_sha256":{"Cargo.toml":"d".repeat(64)},"case_ids":cases,"case_ids_sha256":sha(&cases),"expected":1,"registered":1,"executed":1,"passed":1,"failed":0,"skipped":0,"status":"passed"}],"case_ids_sha256":sha(&cases),"expected":1,"registered":1,"executed":1,"passed":1,"failed":0,"skipped":0,"status":"passed"})
}
fn approval_value() -> Value {
    json!({"schema":"leapterm.source-ci.approval.v1","identity":identity(),"source_ref":"refs/heads/main","base_sha":"a".repeat(40),"catalog_sha256":"c".repeat(64),"workflow_inventory_sha256":"d".repeat(64),"not_before_epoch":1000,"expires_epoch":2000,"requests":CI_STAGES.iter().map(|stage| json!({"stage":stage,"shard_index":0,"shard_count":1,"request_sha256":sha(&serde_json::to_value(request(stage)).unwrap()),"case_ids_sha256":receipt(stage)["case_ids_sha256"]})).collect::<Vec<_>>()})
}
fn approval() -> Approval {
    Approval::parse_at(&approval_value(), 1500).unwrap()
}
fn metadata() -> Value {
    json!({"source_repository":{"full_name":"example-org/private-source","private":true,"default_branch":"main"},"builder_repository":{"full_name":"omnisolo-llc/leapterm-release","private":false,"default_branch":"main"},"candidates":[{"source_ref":"refs/heads/main","source_sha":"a".repeat(40),"base_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"catalog_sha256":"c".repeat(64),"workflow_inventory_sha256":"d".repeat(64),"head_repository":"example-org/private-source","state":"main"}]})
}
fn run() -> Value {
    json!({"identity":identity(),"source_ref":"refs/heads/main","catalog_sha256":"c".repeat(64),"status":"completed","conclusion":"success","jobs":std::iter::once(json!({"name":"policy","status":"completed","conclusion":"success"})).chain(CI_STAGES.iter().map(|s| json!({"name":format!("ci [{s}]"),"status":"completed","conclusion":"success"}))).collect::<Vec<_>>()})
}
fn envelope(stage: &str) -> Value {
    let r = receipt(stage);
    let bytes = serde_json::to_vec(&r).unwrap();
    json!({"schema":1,"purpose":"source-ci-stage-handoff","identity":identity(),"source_ref":"refs/heads/main","stage":stage,"shard_index":0,"shard_count":1,"request_sha256":sha(&serde_json::to_value(request(stage)).unwrap()),"approval_sha256":sha(&approval_value()),"catalog_sha256":"c".repeat(64),"case_ids_sha256":r["case_ids_sha256"],"expires_epoch":2000,"status":"passed","expected":1,"registered":1,"executed":1,"passed":1,"failed":0,"skipped":0,"receipt":{"name":format!("source-ci-{stage}-0-of-1.json"),"size":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes)),"role":"private-evidence"}})
}

#[test]
fn discovery_deduplicates_exact_identity_and_rejects_fork_metadata() {
    let initial = select_candidates(&metadata(), &json!({"runs":[]})).unwrap();
    assert_eq!(initial["candidates"].as_array().unwrap().len(), 1);
    let prior = json!({"runs":[{"source_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"catalog_sha256":"c".repeat(64),"mode":"ci"}]});
    assert_eq!(
        select_candidates(&metadata(), &prior).unwrap()["candidates"],
        json!([])
    );
    let mut bad = metadata();
    bad["candidates"][0]["head_repository"] = json!("fork/source");
    assert!(select_candidates(&bad, &json!({"runs":[]})).is_err());
}
#[test]
fn approval_is_exact_complete_and_has_a_bounded_deadline() {
    assert!(Approval::parse_at(&approval_value(), 1500).is_ok());
    assert!(Approval::parse_at(&approval_value(), 2000).is_err());
    for change in [
        "duplicate",
        "missing",
        "unknown",
        "wide-deadline",
        "request",
    ] {
        let mut bad = approval_value();
        match change {
            "duplicate" => {
                let row = bad["requests"][0].clone();
                bad["requests"].as_array_mut().unwrap().push(row);
            }
            "missing" => {
                bad["requests"].as_array_mut().unwrap().pop();
            }
            "unknown" => {
                bad["allow_ciphertext"] = json!(true);
            }
            "wide-deadline" => {
                bad["expires_epoch"] = json!(100_000);
            }
            _ => {
                bad["requests"][0]["request_sha256"] = json!("0".repeat(64));
            }
        }
        assert!(Approval::parse_at(&bad, 1500).is_err(), "{change}");
    }
}
#[test]
fn owning_case_validator_cannot_green_rewritten_cases_or_counters() {
    let req = request("rust");
    let auth = approval();
    assert!(verify_stage_receipt(&receipt("rust"), &req, &auth).is_ok());
    for change in [
        "skipped",
        "missing",
        "same-count-case",
        "catalog",
        "inner-hash",
        "empty",
        "unknown-role",
    ] {
        let mut bad = receipt("rust");
        match change {
            "skipped" => bad["suites"][0]["skipped"] = json!(1),
            "missing" => bad["expected"] = json!(2),
            "same-count-case" => {
                let cases = json!(["rust:gate:0000::different-case"]);
                bad["suites"][0]["case_ids"] = cases.clone();
                bad["suites"][0]["case_ids_sha256"] = json!(sha(&cases));
                bad["case_ids_sha256"] = json!(sha(&cases));
            }
            "catalog" => bad["catalog_sha256"] = json!("e".repeat(64)),
            "inner-hash" => bad["suites"][0]["case_ids_sha256"] = json!("e".repeat(64)),
            "empty" => bad["suites"] = json!([]),
            _ => {
                bad["encrypted-diagnostic"] =
                    json!({"file":"arbitrary.enc","role":"private-evidence"})
            }
        }
        assert!(verify_stage_receipt(&bad, &req, &auth).is_err(), "{change}");
    }
}

#[test]
fn owning_suite_accepts_the_actual_private_input_digest_map() {
    let mut value = receipt("rust");
    value["suites"][0]["input_sha256"] =
        json!({"Cargo.toml":"d".repeat(64),"Cargo.lock":"f".repeat(64)});
    assert!(verify_stage_receipt(&value, &request("rust"), &approval()).is_ok());
}

#[test]
fn owning_suite_cannot_replace_stage_inputs_with_a_digest_claim() {
    let mut value = receipt("rust");
    value["suites"][0]["input_sha256"] = json!({"Cargo.lock":"f".repeat(64)});
    assert!(verify_stage_receipt(&value, &request("rust"), &approval()).is_err());
    for inputs in [
        json!({}),
        json!({"Cargo.toml":"e".repeat(64)}),
        json!({"Cargo.toml":"d".repeat(64),"../private.env":"f".repeat(64)}),
        json!({"Cargo.toml":"d".repeat(64),".env":"f".repeat(64)}),
    ] {
        value["suites"][0]["input_sha256"] = inputs;
        assert!(verify_stage_receipt(&value, &request("rust"), &approval()).is_err());
    }
    value["suites"][0]["input_sha256"] = json!("f".repeat(64));
    assert!(verify_stage_receipt(&value, &request("rust"), &approval()).is_err());
}

#[test]
fn owning_suite_preserves_registered_unicode_and_bounded_long_case_ids() {
    for case in [
        "example_test.dart::supports native continuity — café".to_owned(),
        format!("registered-{}", "x".repeat(2025)),
    ] {
        let mut value = receipt("flutter-vm");
        value["suites"][0]["kind"] = json!("flutter");
        let id = value["suites"][0]["id"].as_str().unwrap();
        let cases = json!([format!("{id}::{case}")]);
        value["suites"][0]["case_ids"] = cases.clone();
        value["suites"][0]["case_ids_sha256"] = json!(sha(&cases));
        value["case_ids_sha256"] = json!(sha(&cases));
        let mut approved = approval_value();
        let row = approved["requests"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["stage"] == "flutter-vm")
            .unwrap();
        row["case_ids_sha256"] = json!(sha(&cases));
        let auth = Approval::parse_at(&approved, 1500).unwrap();
        assert!(verify_stage_receipt(&value, &request("flutter-vm"), &auth).is_ok());
    }
}
#[test]
fn missing_cancelled_and_old_attempt_results_never_report_success() {
    let req = request("source");
    let handoffs = CI_STAGES
        .iter()
        .map(|stage| envelope(stage))
        .collect::<Vec<_>>();
    assert_eq!(
        source_status(&run(), &handoffs, &req).unwrap()["state"],
        "success"
    );
    let mut missing = run();
    missing["jobs"].as_array_mut().unwrap().pop();
    assert_ne!(
        source_status(&missing, &handoffs, &req).unwrap()["state"],
        "success"
    );
    assert_ne!(
        source_status(&run(), &handoffs[..12], &req).unwrap()["state"],
        "success"
    );
    let mut cancelled = run();
    cancelled["conclusion"] = json!("cancelled");
    assert_ne!(
        source_status(&cancelled, &handoffs, &req).unwrap()["state"],
        "success"
    );
    let mut old = run();
    old["identity"]["attempt"] = json!("2");
    assert!(source_status(&old, &handoffs, &req).is_err());
    let mut stale = handoffs.clone();
    stale[0]["identity"]["source_sha"] = json!("e".repeat(40));
    assert!(source_status(&run(), &stale, &req).is_err());
}

#[derive(Clone)]
struct Seen {
    method: String,
    path: String,
    token: String,
    body: Vec<u8>,
}
type FixtureResponses = Arc<Mutex<BTreeMap<String, (u16, Vec<u8>)>>>;
struct Fixture {
    address: String,
    requests: Arc<Mutex<Vec<Seen>>>,
    assets: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    private: Arc<AtomicBool>,
    ambiguous: Arc<AtomicBool>,
    responses: FixtureResponses,
    dispatch_accept: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let assets = Arc::new(Mutex::new(BTreeMap::<String, Vec<u8>>::new()));
        let private = Arc::new(AtomicBool::new(true));
        let ambiguous = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let responses = Arc::new(Mutex::new(BTreeMap::<String, (u16, Vec<u8>)>::new()));
        let dispatch_accept = Arc::new(AtomicBool::new(true));
        let (r, a, p, amb, s, res, accept_dispatch) = (
            requests.clone(),
            assets.clone(),
            private.clone(),
            ambiguous.clone(),
            stop.clone(),
            responses.clone(),
            dispatch_accept.clone(),
        );
        let worker = thread::spawn(move || {
            let mut created = false;
            let mut dispatched = false;
            let mut labels = BTreeMap::<String, String>::new();
            while !s.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                };
                // BSD/macOS can inherit the listener's nonblocking mode;
                // request reads need blocking I/O with the existing timeout.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                let (end, length) = loop {
                    let n = stream.read(&mut buffer).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length = headers
                            .lines()
                            .find_map(|h| h.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                        if bytes.len() >= end + 4 + length {
                            break (end, length);
                        }
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let mut first = headers.lines().next().unwrap().split_whitespace();
                let method = first.next().unwrap().to_owned();
                let path = first.next().unwrap().to_owned();
                let token = headers
                    .lines()
                    .find_map(|h| h.strip_prefix("Authorization: Bearer "))
                    .unwrap()
                    .to_owned();
                let body = bytes[end + 4..end + 4 + length].to_vec();
                r.lock().unwrap().push(Seen {
                    method: method.clone(),
                    path: path.clone(),
                    token,
                    body: body.clone(),
                });
                let marker = json!({"schema":1,"purpose":"private-source-ci-handoff","identity":identity(),"approval_sha256":sha(&approval_value()),"catalog_sha256":"c".repeat(64)});
                let release = json!({"id":7,"draft":true,"tag_name":"ci-stage/ci-123-1","target_commitish":"a".repeat(40),"body":marker.to_string()});
                let override_response = res
                    .lock()
                    .unwrap()
                    .get(&format!("{method} {path}"))
                    .cloned();
                let (status, response) = if let Some(response) = override_response {
                    response
                } else if path == "/repos/example-org/private-source" {
                    (200,json!({"full_name":"example-org/private-source","private":p.load(Ordering::Relaxed),"default_branch":"main"}).to_string().into_bytes())
                } else if path.starts_with("/repos/example-org/private-source/releases?") {
                    (
                        200,
                        if created { json!([release]) } else { json!([]) }
                            .to_string()
                            .into_bytes(),
                    )
                } else if path == "/repos/example-org/private-source/releases" && method == "POST" {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&body).unwrap()["body"],
                        marker.to_string()
                    );
                    created = true;
                    (201, release.to_string().into_bytes())
                } else if path.starts_with("/repos/example-org/private-source/releases/7/assets?")
                    && method == "GET"
                {
                    let rows=a.lock().unwrap().iter().enumerate().map(|(i,(name,bytes))|json!({"id":i+20,"name":name,"size":bytes.len(),"state":"uploaded","label":labels[name]})).collect::<Vec<_>>();
                    (200, json!(rows).to_string().into_bytes())
                } else if path
                    .starts_with("/repos/example-org/private-source/releases/7/assets?name=")
                    && method == "POST"
                {
                    let name = path
                        .split("name=")
                        .nth(1)
                        .unwrap()
                        .split('&')
                        .next()
                        .unwrap()
                        .to_owned();
                    labels.insert(
                        name.clone(),
                        format!("v1:{:x}:{}", Sha256::digest(&body), body.len()),
                    );
                    a.lock().unwrap().insert(name, body);
                    if amb.swap(false, Ordering::Relaxed) {
                        (500, b"{}".to_vec())
                    } else {
                        (201, b"{}".to_vec())
                    }
                } else if let Some(id) =
                    path.strip_prefix("/repos/example-org/private-source/releases/assets/")
                {
                    let offset = id.parse::<usize>().unwrap() - 20;
                    (200, a.lock().unwrap().values().nth(offset).unwrap().clone())
                } else if path
                    == "/repos/example-org/private-source/statuses/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    && method == "POST"
                {
                    (201, body)
                } else if path
                    == "/repos/omnisolo-llc/leapterm-release/actions/workflows/source-ci.yml/dispatches"
                    && method == "POST"
                {
                    dispatched = accept_dispatch.load(Ordering::Relaxed);
                    if !dispatched || amb.swap(false, Ordering::Relaxed) {
                        (500, b"{}".to_vec())
                    } else {
                        (204, Vec::new())
                    }
                } else if path.starts_with(
                    "/repos/omnisolo-llc/leapterm-release/actions/workflows/source-ci.yml/runs?",
                ) && method == "GET"
                {
                    let runs = if dispatched {
                        vec![
                            json!({"id":789,"event":"workflow_dispatch","head_branch":"main","repository":{"full_name":"omnisolo-llc/leapterm-release"},"head_sha":"b".repeat(40),"display_title":format!("source-ci:{}",correlation_id("example-org/private-source",&"a".repeat(40),&"b".repeat(40),"ci"))}),
                        ]
                    } else {
                        vec![]
                    };
                    (
                        200,
                        json!({"total_count":runs.len(),"workflow_runs":runs})
                            .to_string()
                            .into_bytes(),
                    )
                } else {
                    panic!("unexpected owned HTTP route: {method} {path}");
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        Self {
            address,
            requests,
            assets,
            private,
            ambiguous,
            responses,
            dispatch_accept,
            stop,
            worker: Some(worker),
        }
    }
    fn response(&self, method: &str, path: &str, value: Value) {
        self.responses.lock().unwrap().insert(
            format!("{method} {path}"),
            (200, value.to_string().into_bytes()),
        );
    }
    fn environment(&self, dir: &std::path::Path) -> Environment {
        let executable = dir.join(if cfg!(windows) { "gh.exe" } else { "gh" });
        fs::copy(env!("CARGO_BIN_EXE_source-api-fixture"), executable).unwrap();
        fs::write(dir.join("fixture-address"), &self.address).unwrap();
        let mut env = Environment::from([
            ("PATH".into(), dir.to_string_lossy().into_owned()),
            ("GITHUB_TOKEN".into(), "public-fixture".into()),
            (
                "SOURCE_REPOSITORY".into(),
                "example-org/private-source".into(),
            ),
            ("SOURCE_METADATA_READ_TOKEN".into(), "source-fixture".into()),
            (
                "SOURCE_CI_APPROVAL_READ_TOKEN".into(),
                "approval-fixture".into(),
            ),
            (
                "SOURCE_CI_HANDOFF_WRITE_TOKEN".into(),
                "writer-fixture".into(),
            ),
            (
                "SOURCE_CI_HANDOFF_READ_TOKEN".into(),
                "reader-fixture".into(),
            ),
            ("SOURCE_CI_STATUS_TOKEN".into(), "status-fixture".into()),
        ]);
        // Windows socket providers need the OS location in an isolated client
        // environment. The variable lookup is case-insensitive on Windows.
        if let Ok(value) = std::env::var("SYSTEMROOT") {
            env.insert("SYSTEMROOT".into(), value);
        }
        env
    }
    fn api(&self, dir: &std::path::Path, role: Role) -> GitHubApi {
        let env = self.environment(dir);
        GitHubApi::new(&env, dir, role).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn owned_http_upload_readback_retry_and_scope_checks_are_causal() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source-ci-stage.json");
    fs::write(&path, serde_json::to_vec(&receipt("rust")).unwrap()).unwrap();
    let mut api = fixture.api(dir.path(), Role::HandoffWrite);
    fixture.ambiguous.store(true, Ordering::Relaxed);
    retain_stage_with(&mut api, &approval(), &request("rust"), &path).unwrap();
    let uploads = fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.method == "POST" && r.path.contains("assets?name="))
        .count();
    assert_eq!(uploads, 2, "receipt and envelope only");
    retain_stage_with(&mut api, &approval(), &request("rust"), &path).unwrap();
    assert_eq!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST" && r.path.contains("assets?name="))
            .count(),
        uploads,
        "identical retries never rewrite"
    );
    let name = "source-ci-rust-0-of-1.json";
    let mut bytes = fixture.assets.lock().unwrap()[name].clone();
    bytes[0] = b' ';
    fixture.assets.lock().unwrap().insert(name.into(), bytes);
    assert!(
        retain_stage_with(&mut api, &approval(), &request("rust"), &path).is_err(),
        "actual downloaded bytes catch same-size corruption"
    );
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.token == "writer-fixture")
    );
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method != "DELETE" && !r.path.contains("statuses"))
    );
}
#[test]
fn forbidden_files_and_visibility_changes_cannot_reach_an_upload() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    let mut api = fixture.api(dir.path(), Role::HandoffWrite);
    let arbitrary = dir.path().join("encrypted.bin");
    fs::write(&arbitrary, b"sealed material").unwrap();
    assert!(retain_stage_with(&mut api, &approval(), &request("rust"), &arbitrary).is_err());
    assert!(fixture.requests.lock().unwrap().is_empty());
    let path = dir.path().join("source-ci-stage.json");
    fs::write(&path, serde_json::to_vec(&receipt("rust")).unwrap()).unwrap();
    fixture.private.store(false, Ordering::Relaxed);
    assert!(retain_stage_with(&mut api, &approval(), &request("rust"), &path).is_err());
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}

fn trusted_metadata(fixture: &Fixture, approval: &Value) {
    fixture.response("GET","/repos/omnisolo-llc/leapterm-release",json!({"full_name":"omnisolo-llc/leapterm-release","private":false,"default_branch":"main"}));
    fixture.response(
        "GET",
        "/repos/omnisolo-llc/leapterm-release/git/ref/heads/main",
        json!({"ref":"refs/heads/main","object":{"type":"commit","sha":"b".repeat(40)}}),
    );
    fixture.response("GET","/repos/omnisolo-llc/leapterm-release/environments/source-ci-authority/variables/SOURCE_CI_APPROVAL_123_1",json!({"name":"SOURCE_CI_APPROVAL_123_1","value":approval.to_string()}));
    fixture.response("GET","/repos/omnisolo-llc/leapterm-release/environments/source-ci-authority",json!({"id":10,"name":"source-ci-authority","can_admins_bypass":false,"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false},"protection_rules":[{"type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"User","reviewer":{"id":99,"login":"fixture-reviewer"}}]}]}));
    fixture.response("GET","/repos/omnisolo-llc/leapterm-release/actions/runs/123",json!({"id":123,"run_attempt":1,"event":"workflow_dispatch","head_branch":"main","head_sha":"b".repeat(40),"path":".github/workflows/source-ci.yml","repository":{"full_name":"omnisolo-llc/leapterm-release","private":false},"head_repository":{"full_name":"omnisolo-llc/leapterm-release","fork":false},"actor":{"id":55},"status":"completed","conclusion":"success","display_title":format!("source-ci:{}",correlation_id("example-org/private-source",&"a".repeat(40),&"b".repeat(40),"ci"))}));
    fixture.response("GET","/repos/omnisolo-llc/leapterm-release/actions/runs/123/approvals",json!([{"state":"approved","user":{"id":99},"comment":format!("leapterm-source-ci-approval:{}",sha(approval)),"environments":[{"id":10,"name":"source-ci-authority"}]}]));
    fixture.response(
        "GET",
        "/repos/example-org/private-source/git/ref/heads/main",
        json!({"ref":"refs/heads/main","object":{"type":"commit","sha":"a".repeat(40)}}),
    );
    fixture.response("GET",&format!("/repos/example-org/private-source/contents/leapterm-release?ref={}","a".repeat(40)),json!({"type":"submodule","sha":"b".repeat(40),"path":"leapterm-release","submodule_git_url":"https://github.com/omnisolo-llc/leapterm-release.git"}));
    let mapping=json!({"schema":1,"source_revision":"a".repeat(40),"inventory_sha256":"d".repeat(64),"jobs":[{"id":"fixture-only"}]}).to_string();
    fixture.response("GET",&format!("/repos/example-org/private-source/contents/scripts/release/public-ci-migration.json?ref={}","a".repeat(40)),json!({"type":"file","encoding":"base64","size":mapping.len(),"content":base64::engine::general_purpose::STANDARD.encode(mapping)}));
    let jobs=std::iter::once("policy".to_owned()).chain(CI_STAGES.iter().map(|s|format!("ci [{s}]"))).enumerate().map(|(i,name)|json!({"id":i+100,"run_id":123,"run_attempt":1,"head_sha":"b".repeat(40),"name":name,"status":"completed","conclusion":"success","labels":["ubuntu-24.04"],"runner_group_name":"GitHub Actions","runner_name":format!("fixture-runner-{i}")})).collect::<Vec<_>>();
    fixture.response(
        "GET",
        "/repos/omnisolo-llc/leapterm-release/actions/runs/123/attempts/1/jobs?per_page=100&page=1",
        json!({"total_count":jobs.len(),"jobs":jobs}),
    );
}
#[test]
fn owned_http_protected_review_binds_exact_record_and_fresh_metadata() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    trusted_metadata(&fixture, &approval_value());
    let mut public = fixture.api(dir.path(), Role::PublicRead);
    let mut protected = fixture.api(dir.path(), Role::ApprovalRead);
    assert!(acquire_approval(&mut public, &mut protected, "123", "1", 1500).is_ok());
    fixture.response("GET","/repos/omnisolo-llc/leapterm-release/actions/runs/123/approvals",json!([{"state":"approved","user":{"id":99},"comment":format!("leapterm-source-ci-approval:{}","e".repeat(64)),"environments":[{"id":10,"name":"source-ci-authority"}]}]));
    assert!(acquire_approval(&mut public, &mut protected, "123", "1", 1500).is_err());
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
    assert!(fixture.requests.lock().unwrap().iter().all(
        |r| if r.path.contains("/environments/") {
            r.token == "approval-fixture"
        } else {
            r.token == "public-fixture"
        }
    ));
}
#[test]
fn owned_http_changed_head_and_fork_are_denied_before_source_contents() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    trusted_metadata(&fixture, &approval_value());
    let mut source = fixture.api(dir.path(), Role::SourceRead);
    assert!(fresh_source(&mut source, &request("rust"), &approval()).is_ok());
    fixture.requests.lock().unwrap().clear();
    fixture.response(
        "GET",
        "/repos/example-org/private-source/git/ref/heads/main",
        json!({"ref":"refs/heads/main","object":{"type":"commit","sha":"e".repeat(40)}}),
    );
    assert!(fresh_source(&mut source, &request("rust"), &approval()).is_err());
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET" && !r.path.contains("/contents/"))
    );
    let mut approved = approval_value();
    approved["source_ref"] = json!("refs/pull/42/head");
    approved["base_sha"] = json!("c".repeat(40));
    for row in approved["requests"].as_array_mut().unwrap() {
        let mut req = request(row["stage"].as_str().unwrap());
        req.source_ref = "refs/pull/42/head".into();
        row["request_sha256"] = json!(sha(&serde_json::to_value(req).unwrap()));
    }
    let approved = Approval::parse_at(&approved, 1500).unwrap();
    let mut req = request("rust");
    req.source_ref = "refs/pull/42/head".into();
    fixture.requests.lock().unwrap().clear();
    fixture.response("GET","/repos/example-org/private-source/pulls/42",json!({"state":"open","head":{"sha":"a".repeat(40),"repo":{"full_name":"fork/source","private":true}},"base":{"sha":"c".repeat(40),"ref":"main","repo":{"full_name":"example-org/private-source"}}}));
    assert!(fresh_source(&mut source, &req, &approved).is_err());
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET"
                && !r.path.contains("/contents/")
                && !r.path.contains("/compare/"))
    );
}
#[test]
fn owned_http_reporter_cannot_green_missing_evidence_or_execute_source() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut approved = approval_value();
    approved["not_before_epoch"] = json!(now - 10);
    approved["expires_epoch"] = json!(now + 600);
    trusted_metadata(&fixture, &approved);
    let mut env = fixture.environment(dir.path());
    for (key, value) in [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_REPOSITORY", "omnisolo-llc/leapterm-release"),
        ("GITHUB_REF", "refs/heads/main"),
        (
            "GITHUB_WORKFLOW_REF",
            "omnisolo-llc/leapterm-release/.github/workflows/source-ci-report.yml@refs/heads/main",
        ),
        ("GITHUB_EVENT_NAME", "workflow_run"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("SOURCE_CI_REPORT_ENABLED", "true"),
        ("SOURCE_CI_REPORT_RUN_ID", "123"),
        ("SOURCE_CI_REPORT_RUN_ATTEMPT", "1"),
    ] {
        env.insert(key.into(), value.into());
    }
    env.insert("GITHUB_SHA".into(), "b".repeat(40));
    report_cli(&[], &env).unwrap();
    let requests = fixture.requests.lock().unwrap();
    let writes = requests
        .iter()
        .filter(|r| r.method == "POST")
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].path.contains("/statuses/"));
    assert_eq!(writes[0].token, "status-fixture");
    assert_eq!(
        serde_json::from_slice::<Value>(&writes[0].body).unwrap()["state"],
        "failure"
    );
    assert!(requests.iter().all(|r| !r.path.contains("dispatches")
        && !r.path.contains("assets?name=")
        && r.method != "DELETE"));
    drop(requests);
    fixture.requests.lock().unwrap().clear();
    fixture.response(
        "GET",
        "/repos/example-org/private-source/git/ref/heads/main",
        json!({"ref":"refs/heads/main","object":{"type":"commit","sha":"e".repeat(40)}}),
    );
    assert!(report_cli(&[], &env).is_err());
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}
#[test]
fn api_capabilities_cannot_select_another_purpose() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    let mut reader = fixture.api(dir.path(), Role::HandoffRead);
    assert!(
        reader
            .post_json(
                "repos/example-org/private-source/releases",
                &json!({"draft":true})
            )
            .is_err()
    );
    let mut status = fixture.api(dir.path(), Role::Status);
    assert!(status.get_json("repos/example-org/private-source").is_err());
    assert!(
        status
            .post_json(
                "repos/omnisolo-llc/leapterm-release/actions/workflows/source-ci.yml/dispatches",
                &json!({"ref":"main"})
            )
            .is_err()
    );
    assert!(fixture.requests.lock().unwrap().is_empty());
}
#[test]
fn cleanup_plan_preserves_live_referenced_foreign_and_published_data() {
    let now = 1_000_000;
    let marker = json!({"schema":1,"purpose":"private-source-ci-handoff","identity":identity(),"approval_sha256":sha(&approval_value()),"catalog_sha256":"c".repeat(64)});
    let old = json!({"id":7,"draft":true,"referenced":false,"tag_name":"ci-stage/ci-123-1","target_commitish":"a".repeat(40),"body":marker.to_string(),"created_epoch":1000,"run":{"id":"123","attempt":"1","status":"completed","conclusion":"success","completed_epoch":2000},"assets":[{"name":"source-ci-rust-0-of-1.json","size":100,"state":"uploaded"}]});
    let mut releases = vec![old.clone()];
    for change in [
        "live",
        "referenced",
        "published",
        "foreign",
        "owner-asset",
        "fresh",
    ] {
        let mut release = old.clone();
        release["id"] = json!(releases.len() + 7);
        match change {
            "live" => release["run"]["status"] = json!("in_progress"),
            "referenced" => release["referenced"] = json!(true),
            "published" => release["draft"] = json!(false),
            "foreign" => release["body"] = json!("owner draft"),
            "owner-asset" => release["assets"][0]["name"] = json!("owner-private-file.bin"),
            _ => release["run"]["completed_epoch"] = json!(now - 100),
        }
        releases.push(release);
    }
    let metadata = json!({"repository":{"full_name":"example-org/private-source","private":true},"observed_epoch":now,"releases":releases});
    let plan = cleanup_candidates(&metadata, now).unwrap();
    assert_eq!(plan["deletions"].as_array().unwrap().len(), 1);
    assert_eq!(plan["deletions"][0]["release_id"], 7);
    assert!(cleanup_candidates(&metadata, now + 1).is_err());
}

fn discovery_environment(fixture: &Fixture, dir: &std::path::Path) -> Environment {
    trusted_metadata(fixture, &approval_value());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let selection = json!({"schema":"leapterm.source-ci.discovery.v1","builder_sha":"b".repeat(40),"not_before_epoch":now-10,"expires_epoch":now+600,"candidates":[{"source_ref":"refs/heads/main","source_sha":"a".repeat(40),"base_sha":"a".repeat(40),"catalog_sha256":"c".repeat(64),"workflow_inventory_sha256":"d".repeat(64)}]});
    fixture.response("GET","/repos/omnisolo-llc/leapterm-release/environments/source-ci-discovery/variables/SOURCE_CI_DISCOVERY",json!({"name":"SOURCE_CI_DISCOVERY","value":selection.to_string()}));
    let mut env = fixture.environment(dir);
    for (key, value) in [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_REPOSITORY", "omnisolo-llc/leapterm-release"),
        ("GITHUB_REF", "refs/heads/main"),
        (
            "GITHUB_WORKFLOW_REF",
            "omnisolo-llc/leapterm-release/.github/workflows/source-discovery.yml@refs/heads/main",
        ),
        ("GITHUB_EVENT_NAME", "schedule"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("SOURCE_CI_DISCOVERY_ENABLED", "true"),
    ] {
        env.insert(key.into(), value.into());
    }
    env.insert("GITHUB_SHA".into(), "b".repeat(40));
    env
}
#[test]
fn owned_http_ambiguous_dispatch_is_resolved_once_and_never_blindly_retried() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    let env = discovery_environment(&fixture, dir.path());
    fixture.ambiguous.store(true, Ordering::Relaxed);
    discover_cli(&[], &env).unwrap();
    discover_cli(&[], &env).unwrap();
    let requests = fixture.requests.lock().unwrap();
    let posts = requests
        .iter()
        .filter(|r| r.method == "POST")
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 1);
    assert!(posts[0].path.ends_with("/source-ci.yml/dispatches"));
    assert_eq!(posts[0].token, "public-fixture");
    assert!(requests.iter().all(|r| !r.path.contains("/statuses/")
        && !r.path.contains("assets?name=")
        && !r.path.contains("/approvals")));
    drop(requests);
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    let env = discovery_environment(&fixture, dir.path());
    fixture.dispatch_accept.store(false, Ordering::Relaxed);
    assert!(discover_cli(&[], &env).is_err());
    assert_eq!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        1
    );
}
#[test]
fn owned_http_discovery_reads_all_pages_and_rate_limits_before_dispatch() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    let env = discovery_environment(&fixture, dir.path());
    let first=(1..=100).map(|id|json!({"id":id,"event":"workflow_dispatch","head_branch":"main","repository":{"full_name":"omnisolo-llc/leapterm-release"},"head_sha":"b".repeat(40),"display_title":"other-reviewed-request"})).collect::<Vec<_>>();
    let second = json!({"id":101,"event":"workflow_dispatch","head_branch":"main","repository":{"full_name":"omnisolo-llc/leapterm-release"},"head_sha":"b".repeat(40),"display_title":format!("source-ci:{}",correlation_id("example-org/private-source",&"a".repeat(40),&"b".repeat(40),"ci"))});
    let page1 = "/repos/omnisolo-llc/leapterm-release/actions/workflows/source-ci.yml/runs?event=workflow_dispatch&branch=main&per_page=100&page=1";
    let page2 = "/repos/omnisolo-llc/leapterm-release/actions/workflows/source-ci.yml/runs?event=workflow_dispatch&branch=main&per_page=100&page=2";
    fixture.response(
        "GET",
        page1,
        json!({"total_count":101,"workflow_runs":first}),
    );
    fixture.response(
        "GET",
        page2,
        json!({"total_count":101,"workflow_runs":[second]}),
    );
    discover_cli(&[], &env).unwrap();
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.path == page2)
    );
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
    fixture.requests.lock().unwrap().clear();
    fixture
        .responses
        .lock()
        .unwrap()
        .insert(format!("GET {page1}"), (429, b"{}".to_vec()));
    assert!(discover_cli(&[], &env).is_err());
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}
#[test]
fn owned_http_ordinary_release_subtree_requires_exact_public_builder_commit_tree() {
    let fixture = Fixture::start();
    let dir = tempfile::tempdir().unwrap();
    trusted_metadata(&fixture, &approval_value());
    let head = "a".repeat(40);
    let builder_sha = "b".repeat(40);
    let root_tree = "2".repeat(40);
    let builder_tree = "1".repeat(40);
    let child = json!({
        "name": "README.md",
        "path": "leapterm-release/README.md",
        "type": "file",
        "sha": "3".repeat(40),
    });
    let tree_entry = json!({
        "path": "leapterm-release",
        "mode": "040000",
        "type": "tree",
        "sha": builder_tree,
    });
    fixture.response(
        "GET",
        &format!("/repos/example-org/private-source/contents/leapterm-release?ref={head}"),
        json!([child]),
    );
    fixture.response(
        "GET",
        &format!("/repos/example-org/private-source/git/commits/{head}"),
        json!({"sha":head,"tree":{"sha":root_tree}}),
    );
    fixture.response(
        "GET",
        &format!("/repos/example-org/private-source/git/trees/{root_tree}"),
        json!({"sha":root_tree,"truncated":false,"tree":[tree_entry.clone()]}),
    );
    fixture.response(
        "GET",
        &format!("/repos/omnisolo-llc/leapterm-release/git/commits/{builder_sha}"),
        json!({"sha":builder_sha,"tree":{"sha":builder_tree}}),
    );
    let mut source = fixture.api(dir.path(), Role::SourceRead);
    let observed = fresh_source(&mut source, &request("rust"), &approval()).unwrap();
    assert_eq!(observed["source_builder_sha"], builder_sha);

    fixture.response(
        "GET",
        &format!("/repos/omnisolo-llc/leapterm-release/git/commits/{builder_sha}"),
        json!({"sha":builder_sha,"tree":{"sha":"9".repeat(40)}}),
    );
    assert!(fresh_source(&mut source, &request("rust"), &approval()).is_err());

    fixture.response(
        "GET",
        &format!("/repos/omnisolo-llc/leapterm-release/git/commits/{builder_sha}"),
        json!({"sha":builder_sha,"tree":{"sha":builder_tree}}),
    );
    fixture.response(
        "GET",
        &format!("/repos/example-org/private-source/git/trees/{root_tree}"),
        json!({"sha":root_tree,"truncated":true,"tree":[tree_entry]}),
    );
    assert!(fresh_source(&mut source, &request("rust"), &approval()).is_err());
}
