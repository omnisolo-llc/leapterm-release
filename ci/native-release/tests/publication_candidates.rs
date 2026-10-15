use omni_release_launcher::{
    Environment,
    publication_candidates::{self, ReleaseApi},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

fn canonical_tempdir() -> tempfile::TempDir {
    let root = std::env::temp_dir().canonicalize().unwrap();
    tempfile::tempdir_in(root).unwrap()
}

fn environment() -> Environment {
    Environment::from([
        ("GITHUB_ACTIONS".into(), "true".into()),
        ("GITHUB_EVENT_NAME".into(), "workflow_dispatch".into()),
        ("GITHUB_REPOSITORY".into(), "omnisolo-llc/leapterm-release".into()),
        ("GITHUB_REF".into(), "refs/heads/main".into()),
        ("GITHUB_WORKFLOW_REF".into(), "omnisolo-llc/leapterm-release/.github/workflows/release.yml@refs/heads/main".into()),
        ("GITHUB_SHA".into(), "b".repeat(40)),
        ("GITHUB_RUN_ID".into(), "42".into()),
        ("GITHUB_RUN_ATTEMPT".into(), "2".into()),
        ("SOURCE_REPOSITORY".into(), "omnisolo-llc/leapterm".into()),
        ("SOURCE_BRANCH".into(), "main".into()),
        ("RELEASE_TARGET".into(), "publish".into()),
        ("RESOLVED_SOURCE_SHA".into(), "a".repeat(40)),
        ("RELEASE_REQUEST".into(), json!({"source_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"version":"1.2.3","build_number":"42","build_only":false,"ios_action":"submit"}).to_string()),
    ])
}
fn plan(directory: &Path) -> Value {
    let env = environment();
    let release = publication_candidates::request(&env).unwrap();
    let mut files = serde_json::Map::new();
    for name in ["omniterm-1.2.3-linux-x64.tar.gz", "SHA256SUMS"] {
        let bytes = format!("fixture bytes for {name}\n").into_bytes();
        fs::write(directory.join(name), &bytes).unwrap();
        files.insert(name.into(), json!({"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes)),"content_type":"application/octet-stream"}));
    }
    json!({"schema":1,"identity":publication_candidates::identity(&env).unwrap(),"release":serde_json::from_str::<Value>(&release.normalized().unwrap()).unwrap(),"repository":"omnisolo-llc/leapterm-release","files":files})
}

#[test]
fn public_plan_binds_real_files_and_rejects_empty_changed_or_unsafe_inputs() {
    let directory = canonical_tempdir();
    let value = plan(directory.path());
    publication_candidates::read_plan(&value, &environment(), directory.path()).unwrap();
    let name = "omniterm-1.2.3-linux-x64.tar.gz";
    let original = fs::read(directory.path().join(name)).unwrap();
    let mut changed = original.clone();
    changed[0] ^= 1;
    fs::write(directory.path().join(name), &changed).unwrap();
    assert!(publication_candidates::read_plan(&value, &environment(), directory.path()).is_err());
    fs::write(directory.path().join(name), original).unwrap();
    for (field, replacement) in [
        ("schema", json!(true)),
        ("repository", json!("omnisolo-llc/leapterm")),
        ("files", json!({})),
        ("extra", json!(true)),
    ] {
        let mut invalid = value.clone();
        invalid[field] = replacement;
        assert!(
            publication_candidates::read_plan(&invalid, &environment(), directory.path()).is_err()
        );
    }
    let mut stale = environment();
    stale.insert("GITHUB_RUN_ATTEMPT".into(), "3".into());
    assert!(publication_candidates::read_plan(&value, &stale, directory.path()).is_err());
    fs::write(
        directory.path().join("diagnostics.sealed"),
        b"private fixture",
    )
    .unwrap();
    assert!(publication_candidates::read_plan(&value, &environment(), directory.path()).is_err());
}

#[test]
fn public_plan_defaults_to_normal_notes_and_preserves_existing_plan_identity() {
    let directory = canonical_tempdir();
    let mut value = plan(directory.path());
    let mut env = environment();
    let legacy = publication_candidates::read_plan(&value, &env, directory.path()).unwrap();
    assert_eq!(
        legacy.notes(),
        "LeapTerm v1.2.3 (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa).\n<!-- native-publication:4b102a50deb48ce723f490f9e29612962283b52b6bedf96194c9e45d006875b5 -->"
    );
    env.insert("BUILD_CONFIG".into(), json!({}).to_string());
    assert_eq!(
        publication_candidates::read_plan(&value, &env, directory.path())
            .unwrap()
            .notes(),
        legacy.notes()
    );
    value["windows_self_signed"] = json!(false);
    env.insert(
        "BUILD_CONFIG".into(),
        json!({"LEAP_WINDOWS_SELF_SIGNED":"false"}).to_string(),
    );
    assert_eq!(
        publication_candidates::read_plan(&value, &env, directory.path())
            .unwrap()
            .notes(),
        legacy.notes()
    );
}

#[test]
fn public_plan_self_signed_notes_disclose_windows_trust_and_openpgp_verification() {
    let directory = canonical_tempdir();
    let mut value = plan(directory.path());
    value["windows_self_signed"] = json!(true);
    let mut env = environment();
    env.insert(
        "BUILD_CONFIG".into(),
        json!({"LEAP_WINDOWS_SELF_SIGNED":"true"}).to_string(),
    );
    let checked = publication_candidates::read_plan(&value, &env, directory.path()).unwrap();
    let notes = checked.notes();
    assert!(notes.contains("self-signed Authenticode"));
    assert!(notes.contains("Windows may show trust warnings"));
    assert!(notes.contains("not trusted by a public certificate authority"));
    assert!(notes.contains("detached OpenPGP package signatures"));
    assert!(notes.contains("reviewed release signing key"));
    assert!(notes.contains("omniterm-windows-signing.cer as a public DER certificate"));
    assert!(notes.contains("no private key material is included"));
    assert!(notes.starts_with(&format!("LeapTerm v1.2.3 ({}).\n", "a".repeat(40))));
    assert!(notes.ends_with(" -->"));
    assert!(notes.contains("<!-- native-publication:"));
}

#[test]
fn public_plan_self_signing_must_match_explicit_build_configuration() {
    let directory = canonical_tempdir();
    let mut value = plan(directory.path());
    let mut env = environment();
    env.insert(
        "BUILD_CONFIG".into(),
        json!({"LEAP_WINDOWS_SELF_SIGNED":"true"}).to_string(),
    );
    for declaration in [None, Some(false)] {
        if let Some(declaration) = declaration {
            value["windows_self_signed"] = json!(declaration);
        }
        assert_eq!(
            publication_candidates::read_plan(&value, &env, directory.path()).err(),
            Some("Windows signing disclosure differs from build configuration")
        );
    }
    value["windows_self_signed"] = json!(true);
    env.remove("BUILD_CONFIG");
    assert_eq!(
        publication_candidates::read_plan(&value, &env, directory.path()).err(),
        Some("Windows signing disclosure differs from build configuration")
    );
    for config in [json!({}), json!({"LEAP_WINDOWS_SELF_SIGNED":"false"})] {
        env.insert("BUILD_CONFIG".into(), config.to_string());
        assert_eq!(
            publication_candidates::read_plan(&value, &env, directory.path()).err(),
            Some("Windows signing disclosure differs from build configuration")
        );
    }
}

#[test]
fn public_plan_self_signing_requires_a_boolean_plan_field_and_string_build_flag() {
    let directory = canonical_tempdir();
    let value = plan(directory.path());
    let mut env = environment();
    for flag in [
        json!(true),
        json!(false),
        json!(null),
        json!(1),
        json!("TRUE"),
        json!("true "),
        json!(""),
        json!([]),
        json!({}),
    ] {
        env.insert(
            "BUILD_CONFIG".into(),
            json!({"LEAP_WINDOWS_SELF_SIGNED":flag}).to_string(),
        );
        assert_eq!(
            publication_candidates::read_plan(&value, &env, directory.path()).err(),
            Some("Invalid LEAP_WINDOWS_SELF_SIGNED in build configuration")
        );
    }
    for raw in ["", "[]", "null", "true", "\"true\"", "not-json"] {
        env.insert("BUILD_CONFIG".into(), raw.into());
        assert!(publication_candidates::read_plan(&value, &env, directory.path()).is_err());
    }
    env.insert(
        "BUILD_CONFIG".into(),
        json!({"LEAP_WINDOWS_SELF_SIGNED":"true"}).to_string(),
    );
    for declaration in [json!(null), json!("true"), json!(1), json!([]), json!({})] {
        let mut invalid = value.clone();
        invalid["windows_self_signed"] = declaration;
        assert_eq!(
            publication_candidates::read_plan(&invalid, &env, directory.path()).err(),
            Some("Invalid public publication plan")
        );
    }
}

#[test]
fn verification_scope_drops_publication_provider_and_checkout_credentials() {
    let mut env = environment();
    for key in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "PRIVATE_RELEASE_TOKEN",
        "SOURCE_DEPLOY_KEY",
        "SOURCE_SUBMODULE_TOKEN",
        "LEAP_PROVIDER_TOKEN",
        "APP_STORE_CONNECT_PASSWORD",
        "GITHUB_OUTPUT",
    ] {
        env.insert(key.into(), "fixture secret".into());
    }
    env.insert("SIGNING_CONFIG".into(), "protected signing fixture".into());
    let child = publication_candidates::verification_environment(&env);
    assert_eq!(child["SIGNING_CONFIG"], "protected signing fixture");
    for key in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "PRIVATE_RELEASE_TOKEN",
        "SOURCE_DEPLOY_KEY",
        "SOURCE_SUBMODULE_TOKEN",
        "LEAP_PROVIDER_TOKEN",
        "APP_STORE_CONNECT_PASSWORD",
        "GITHUB_OUTPUT",
    ] {
        assert!(!child.contains_key(key), "{key}");
    }
    let mut unsigned: Value = serde_json::from_str(&env["RELEASE_REQUEST"]).unwrap();
    unsigned["build_only"] = json!(true);
    unsigned["ios_action"] = json!("skip");
    env.insert("RELEASE_REQUEST".into(), unsigned.to_string());
    assert!(publication_candidates::request(&env).is_err());
}

#[test]
fn symbolic_and_hardlinked_public_assets_are_rejected() {
    let directory = canonical_tempdir();
    let value = plan(directory.path());
    let name = "omniterm-1.2.3-linux-x64.tar.gz";
    let outside = canonical_tempdir();
    fs::rename(directory.path().join(name), outside.path().join(name)).unwrap();
    fs::hard_link(outside.path().join(name), directory.path().join(name)).unwrap();
    assert!(publication_candidates::read_plan(&value, &environment(), directory.path()).is_err());
    fs::remove_file(directory.path().join(name)).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path().join(name), directory.path().join(name)).unwrap();
        assert!(
            publication_candidates::read_plan(&value, &environment(), directory.path()).is_err()
        );
    }
}

#[test]
fn stored_verifier_and_plan_cannot_authorize_their_own_custody_hashes() {
    let runner = canonical_tempdir();
    let root = runner.path().join(publication_candidates::DIRECTORY);
    fs::create_dir_all(root.join("files")).unwrap();
    let value = plan(&root.join("files"));
    let plan_bytes = serde_json::to_vec(&value).unwrap();
    fs::write(root.join("plan.json"), &plan_bytes).unwrap();
    let binary_name = if cfg!(windows) {
        "native-verifier.exe"
    } else {
        "native-verifier"
    };
    let binary_bytes = b"fixture bytes that must never execute";
    fs::write(root.join(binary_name), binary_bytes).unwrap();
    let verifier_hash = format!("{:x}", Sha256::digest(binary_bytes));
    let plan_hash = format!("{:x}", Sha256::digest(&plan_bytes));
    let mut env = environment();
    env.insert(
        "RUNNER_TEMP".into(),
        runner.path().to_string_lossy().into_owned(),
    );
    fs::write(root.join("native-verifier.json"),json!({"schema":1,"identity":publication_candidates::identity(&env).unwrap(),"bytes":binary_bytes.len(),"sha256":verifier_hash}).to_string()).unwrap();
    env.insert("APPROVED_NATIVE_VERIFIER_SHA256".into(), "c".repeat(64));
    env.insert("APPROVED_PUBLICATION_PLAN_SHA256".into(), plan_hash.clone());
    assert_eq!(
        publication_candidates::verify_prepared(&env).err(),
        Some("Native verifier does not belong to this release")
    );
    env.insert("APPROVED_NATIVE_VERIFIER_SHA256".into(), verifier_hash);
    env.insert("APPROVED_PUBLICATION_PLAN_SHA256".into(), "d".repeat(64));
    assert_eq!(
        publication_candidates::verify_prepared(&env).err(),
        Some("Native publication plan differs from trusted preparation output")
    );
    env.insert("APPROVED_PUBLICATION_PLAN_SHA256".into(), plan_hash);
    fs::write(root.join(binary_name), b"changed verifier bytes").unwrap();
    assert_eq!(
        publication_candidates::verify_prepared(&env).err(),
        Some("Approved native verifier changed")
    );
}

// An actual HTTP fixture is used below; only the API adapter is injectable.
// Neither the fixture nor these tests can contact GitHub or hold a write token.
struct HttpFixture {
    base: String,
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    bodies: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl HttpFixture {
    fn start(responses: Vec<(String, Vec<u8>)>) -> Self {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = listener.local_addr().unwrap().to_string();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = requests.clone();
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed_bodies = bodies.clone();
        listener.set_nonblocking(true).unwrap();
        let join = std::thread::spawn(move || {
            for (expected, body) in responses {
                let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < until =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(5))
                        }
                        Err(error) => panic!("Fixture request unavailable: {expected}: {error}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                    .unwrap();
                let mut raw = Vec::new();
                loop {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    raw.push(byte[0]);
                    if raw.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let header = String::from_utf8(raw).unwrap();
                let first = header.lines().next().unwrap().to_owned();
                observed.lock().unwrap().push(first.clone());
                assert_eq!(first, expected);
                let length = header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                assert!(length <= 65536);
                let mut sent = vec![0; length];
                socket.read_exact(&mut sent).unwrap();
                observed_bodies.lock().unwrap().push(sent);
                let status = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|value| value["status"].as_u64())
                    .filter(|status| *status >= 400)
                    .unwrap_or(200);
                write!(
                    socket,
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                socket.write_all(&body).unwrap();
            }
        });
        Self {
            base,
            requests,
            bodies,
            join: Some(join),
        }
    }
    fn exchange(
        &self,
        method: &str,
        endpoint: &str,
        sent: &[u8],
    ) -> omni_release_launcher::Result<Vec<u8>> {
        use std::io::{Read, Write};
        let mut socket = std::net::TcpStream::connect(&self.base).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        write!(
            socket,
            "{method} /{endpoint} HTTP/1.1\r\nHost: fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",sent.len()
        )
        .unwrap();
        socket.write_all(sent).unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).unwrap();
        let body = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let status = String::from_utf8_lossy(&bytes[..body])
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        if status != 200 {
            return Err("Fixture HTTP error");
        }
        Ok(bytes[body..].to_vec())
    }
}
impl ReleaseApi for HttpFixture {
    fn get_json(&mut self, endpoint: &str) -> omni_release_launcher::Result<Value> {
        serde_json::from_slice(&self.exchange("GET", endpoint, &[])?)
            .map_err(|_| "Fixture JSON failure")
    }
    fn write_json(
        &mut self,
        method: &str,
        endpoint: &str,
        body: &Value,
    ) -> omni_release_launcher::Result<Value> {
        serde_json::from_slice(&self.exchange(
            method,
            endpoint,
            &serde_json::to_vec(body).unwrap(),
        )?)
        .map_err(|_| "Fixture JSON failure")
    }
    fn upload(
        &mut self,
        release: u64,
        name: &str,
        path: &Path,
    ) -> omni_release_launcher::Result<Value> {
        serde_json::from_slice(&self.exchange(
            "POST",
            &format!("repos/omnisolo-llc/leapterm-release/releases/{release}/assets?name={name}"),
            &fs::read(path).unwrap(),
        )?)
        .map_err(|_| "Fixture JSON failure")
    }
    fn download(&mut self, asset: u64, output: &Path) -> omni_release_launcher::Result<()> {
        fs::write(
            output,
            self.exchange(
                "GET",
                &format!("repos/omnisolo-llc/leapterm-release/releases/assets/{asset}"),
                &[],
            )?,
        )
        .map_err(|_| "Fixture file failure")
    }
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            if std::thread::panicking() {
                let _ = join.join();
            } else {
                join.join().unwrap();
            }
        }
    }
}

#[test]
fn existing_public_release_is_verified_by_download_and_never_overwritten() {
    let directory = canonical_tempdir();
    let value = plan(directory.path());
    let checked =
        publication_candidates::read_plan(&value, &environment(), directory.path()).unwrap();
    let mut assets = Vec::new();
    let mut replies = vec![
        ("GET /repos/omnisolo-llc/leapterm-release HTTP/1.1".into(), json!({"full_name":"omnisolo-llc/leapterm-release","private":false}).to_string().into_bytes()),
        ("GET /repos/omnisolo-llc/leapterm-release/releases?per_page=100&page=1 HTTP/1.1".into(), json!([{"id":7,"tag_name":"v1.2.3","draft":false,"prerelease":false,"target_commitish":"b".repeat(40),"body":checked.notes()}]).to_string().into_bytes()),
    ];
    let mut downloads = BTreeMap::new();
    for (index, (name, record)) in checked.files().iter().enumerate() {
        let id = index as u64 + 11;
        assets.push(json!({"id":id,"name":name,"size":record.bytes,"state":"uploaded"}));
        downloads.insert(id, fs::read(directory.path().join(name)).unwrap());
    }
    replies.push((
        "GET /repos/omnisolo-llc/leapterm-release/releases/7/assets?per_page=100 HTTP/1.1".into(),
        Value::Array(assets).to_string().into_bytes(),
    ));
    for (id, bytes) in downloads {
        replies.push((
            format!("GET /repos/omnisolo-llc/leapterm-release/releases/assets/{id} HTTP/1.1"),
            bytes,
        ));
    }
    let mut fixture = HttpFixture::start(replies);
    assert_eq!(
        publication_candidates::publish(&checked, &mut fixture).unwrap(),
        publication_candidates::Publication::AlreadyPublished
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 5);
}

fn response(method: &str, endpoint: &str, value: Value) -> (String, Vec<u8>) {
    (
        format!("{method} /{endpoint} HTTP/1.1"),
        value.to_string().into_bytes(),
    )
}
fn public_repository() -> (String, Vec<u8>) {
    response(
        "GET",
        "repos/omnisolo-llc/leapterm-release",
        json!({"full_name":"omnisolo-llc/leapterm-release","private":false}),
    )
}
fn existing(plan: &publication_candidates::Plan, draft: bool) -> Value {
    json!({"id":7,"tag_name":"v1.2.3","draft":draft,"prerelease":false,"target_commitish":"b".repeat(40),"body":plan.notes()})
}

#[test]
fn ambiguous_create_failure_never_uploads_over_existing_release_bytes() {
    let directory = canonical_tempdir();
    let value = plan(directory.path());
    let checked =
        publication_candidates::read_plan(&value, &environment(), directory.path()).unwrap();
    let mut fixture = HttpFixture::start(vec![
        public_repository(),
        response(
            "GET",
            "repos/omnisolo-llc/leapterm-release/releases?per_page=100&page=1",
            json!([]),
        ),
        response(
            "POST",
            "repos/omnisolo-llc/leapterm-release/releases",
            json!({"status":502}),
        ),
    ]);
    assert!(publication_candidates::publish(&checked, &mut fixture).is_err());
    let bodies = fixture.bodies.lock().unwrap();
    let created: Value = serde_json::from_slice(&bodies[2]).unwrap();
    assert_eq!(created["draft"], true);
    assert_eq!(created["body"], checked.notes());
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
}

#[test]
fn api_denial_does_not_look_like_absence_or_authorize_creation() {
    let directory = canonical_tempdir();
    let value = plan(directory.path());
    let checked =
        publication_candidates::read_plan(&value, &environment(), directory.path()).unwrap();
    let mut fixture = HttpFixture::start(vec![response(
        "GET",
        "repos/omnisolo-llc/leapterm-release",
        json!({"status":403}),
    )]);
    assert!(publication_candidates::publish(&checked, &mut fixture).is_err());
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
}

#[test]
fn changed_or_incomplete_published_assets_fail_without_mutation() {
    for tamper in [false, true] {
        let directory = canonical_tempdir();
        let value = plan(directory.path());
        let checked =
            publication_candidates::read_plan(&value, &environment(), directory.path()).unwrap();
        let (name, record) = checked.files().first_key_value().unwrap();
        let mut bytes = fs::read(directory.path().join(name)).unwrap();
        if tamper {
            bytes[0] ^= 1;
        }
        let mut fixture = HttpFixture::start(vec![
            public_repository(),
            response(
                "GET",
                "repos/omnisolo-llc/leapterm-release/releases?per_page=100&page=1",
                json!([existing(&checked, false)]),
            ),
            response(
                "GET",
                "repos/omnisolo-llc/leapterm-release/releases/7/assets?per_page=100",
                json!([{"id":11,"name":name,"state":"uploaded","size":record.bytes}]),
            ),
            (
                "GET /repos/omnisolo-llc/leapterm-release/releases/assets/11 HTTP/1.1".into(),
                bytes,
            ),
        ]);
        assert!(publication_candidates::publish(&checked, &mut fixture).is_err());
        assert_eq!(fixture.requests.lock().unwrap().len(), 4);
    }
}

#[test]
fn a_matching_draft_only_adds_missing_files_and_promotes_after_readback() {
    let directory = canonical_tempdir();
    let value = plan(directory.path());
    let checked =
        publication_candidates::read_plan(&value, &environment(), directory.path()).unwrap();
    let records = checked.files();
    let (first, first_record) = records.first_key_value().unwrap();
    let (last, last_record) = records.last_key_value().unwrap();
    let first_asset = json!({"id":11,"name":first,"state":"uploaded","size":first_record.bytes});
    let last_asset = json!({"id":12,"name":last,"state":"uploaded","size":last_record.bytes});
    let first_bytes = fs::read(directory.path().join(first)).unwrap();
    let last_bytes = fs::read(directory.path().join(last)).unwrap();
    let mut replies = vec![
        public_repository(),
        response(
            "GET",
            "repos/omnisolo-llc/leapterm-release/releases?per_page=100&page=1",
            json!([existing(&checked, true)]),
        ),
        response(
            "GET",
            "repos/omnisolo-llc/leapterm-release/releases/7/assets?per_page=100",
            json!([first_asset]),
        ),
        (
            "GET /repos/omnisolo-llc/leapterm-release/releases/assets/11 HTTP/1.1".into(),
            first_bytes.clone(),
        ),
        response(
            "POST",
            &format!("repos/omnisolo-llc/leapterm-release/releases/7/assets?name={last}"),
            last_asset.clone(),
        ),
    ];
    let complete = || {
        vec![
            response(
                "GET",
                "repos/omnisolo-llc/leapterm-release/releases/7/assets?per_page=100",
                json!([first_asset, last_asset]),
            ),
            (
                "GET /repos/omnisolo-llc/leapterm-release/releases/assets/11 HTTP/1.1".into(),
                first_bytes.clone(),
            ),
            (
                "GET /repos/omnisolo-llc/leapterm-release/releases/assets/12 HTTP/1.1".into(),
                last_bytes.clone(),
            ),
        ]
    };
    replies.extend(complete());
    replies.push(response(
        "PATCH",
        "repos/omnisolo-llc/leapterm-release/releases/7",
        existing(&checked, false),
    ));
    replies.push(response(
        "GET",
        "repos/omnisolo-llc/leapterm-release/releases/7",
        existing(&checked, false),
    ));
    replies.extend(complete());
    let mut fixture = HttpFixture::start(replies);
    assert_eq!(
        publication_candidates::publish(&checked, &mut fixture).unwrap(),
        publication_candidates::Publication::Published
    );
    let bodies = fixture.bodies.lock().unwrap();
    assert_eq!(bodies[4], last_bytes);
    let promotion: Value = serde_json::from_slice(&bodies[8]).unwrap();
    assert_eq!(promotion, json!({"draft":false,"make_latest":"true"}));
    assert_eq!(fixture.requests.lock().unwrap().len(), 13);
}

#[test]
fn an_unreviewed_asset_or_other_attempt_release_cannot_be_adopted() {
    for changed_body in [false, true] {
        let directory = canonical_tempdir();
        let value = plan(directory.path());
        let checked =
            publication_candidates::read_plan(&value, &environment(), directory.path()).unwrap();
        let mut release = existing(&checked, true);
        if changed_body {
            release["body"] = json!("another release attempt");
        }
        let mut replies = vec![
            public_repository(),
            response(
                "GET",
                "repos/omnisolo-llc/leapterm-release/releases?per_page=100&page=1",
                json!([release]),
            ),
        ];
        if !changed_body {
            replies.push(response(
                "GET",
                "repos/omnisolo-llc/leapterm-release/releases/7/assets?per_page=100",
                json!([{"id":11,"name":"ios-private-artifact.json","state":"uploaded","size":99}]),
            ));
        }
        let mut fixture = HttpFixture::start(replies);
        assert!(publication_candidates::publish(&checked, &mut fixture).is_err());
        assert!(
            fixture
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| request.starts_with("GET "))
        );
    }
}

#[test]
fn a_current_proof_legacy_draft_binds_notes_only_after_every_asset_matches() {
    for tamper in [false, true] {
        let directory = canonical_tempdir();
        let mut value = plan(directory.path());
        // This HTTP test starts after native signature verification. The
        // private helper tests own genuine cryptographic provenance checks.
        let provenance = json!({"source_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"run_id":"42","attempt":"2","version":"1.2.3","build_number":"42","proof":"e".repeat(64)});
        let name = "omniterm-1.2.3-release-provenance.json";
        let bytes = serde_json::to_vec(&provenance).unwrap();
        fs::write(directory.path().join(name), &bytes).unwrap();
        value["files"][name] = json!({"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes)),"content_type":"application/json"});
        let checked =
            publication_candidates::read_plan(&value, &environment(), directory.path()).unwrap();
        let mut legacy = existing(&checked, true);
        legacy["body"] = json!(format!("<!-- release-attempt:{} -->", "e".repeat(64)));
        let assets=checked.files().iter().enumerate().map(|(index,(name,record))|json!({"id":index as u64+11,"name":name,"size":record.bytes,"state":"uploaded"})).collect::<Vec<_>>();
        let mut replies = vec![
            public_repository(),
            response(
                "GET",
                "repos/omnisolo-llc/leapterm-release/releases?per_page=100&page=1",
                json!([legacy]),
            ),
            response(
                "GET",
                "repos/omnisolo-llc/leapterm-release/releases/7/assets?per_page=100",
                json!(assets),
            ),
        ];
        for (index, asset) in assets.iter().enumerate() {
            let mut bytes =
                fs::read(directory.path().join(asset["name"].as_str().unwrap())).unwrap();
            if tamper {
                bytes[0] ^= 1;
            }
            replies.push((
                format!(
                    "GET /repos/omnisolo-llc/leapterm-release/releases/assets/{} HTTP/1.1",
                    index + 11
                ),
                bytes,
            ));
            if tamper {
                break;
            }
        }
        if !tamper {
            replies.push(response(
                "PATCH",
                "repos/omnisolo-llc/leapterm-release/releases/7",
                existing(&checked, true),
            ));
            for phase in 0..2 {
                replies.push(response(
                    "GET",
                    "repos/omnisolo-llc/leapterm-release/releases/7/assets?per_page=100",
                    json!(assets),
                ));
                for (index, asset) in assets.iter().enumerate() {
                    replies.push((
                        format!(
                            "GET /repos/omnisolo-llc/leapterm-release/releases/assets/{} HTTP/1.1",
                            index + 11
                        ),
                        fs::read(directory.path().join(asset["name"].as_str().unwrap())).unwrap(),
                    ));
                }
                if phase == 0 {
                    replies.push(response(
                        "PATCH",
                        "repos/omnisolo-llc/leapterm-release/releases/7",
                        existing(&checked, false),
                    ));
                    replies.push(response(
                        "GET",
                        "repos/omnisolo-llc/leapterm-release/releases/7",
                        existing(&checked, false),
                    ));
                }
            }
        }
        let mut fixture = HttpFixture::start(replies);
        let result = publication_candidates::publish(&checked, &mut fixture);
        if tamper {
            assert!(result.is_err());
            assert!(
                fixture
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|request| request.starts_with("GET "))
            );
        } else {
            assert_eq!(
                result.unwrap(),
                publication_candidates::Publication::Published
            );
            let bodies = fixture.bodies.lock().unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&bodies[6]).unwrap(),
                json!({"body":checked.notes()})
            );
            assert_eq!(fixture.requests.lock().unwrap().len(), 17);
        }
    }
}

#[test]
fn azure_oidc_and_dll_paths_reach_only_full_windows_signing() {
    let mut env = environment();
    for name in [
        "LEAP_WINDOWS_ARTIFACT_SIGNING_DLIB",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ] {
        env.insert(name.into(), "fixture scoped signing input".into());
    }
    assert!(
        !publication_candidates::verification_environment(&env)
            .contains_key("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    );
    env.insert("RELEASE_TARGET".into(), "windows".into());
    let full = publication_candidates::verification_environment(&env);
    for name in [
        "LEAP_WINDOWS_ARTIFACT_SIGNING_DLIB",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ] {
        assert_eq!(full[name], "fixture scoped signing input");
    }
    let mut request: Value = serde_json::from_str(&env["RELEASE_REQUEST"]).unwrap();
    request["build_only"] = json!(true);
    request["ios_action"] = json!("skip");
    env.insert("RELEASE_REQUEST".into(), request.to_string());
    let unsigned = publication_candidates::verification_environment(&env);
    for name in [
        "LEAP_WINDOWS_ARTIFACT_SIGNING_DLIB",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ] {
        assert!(!unsigned.contains_key(name));
    }
}
#[test]
fn publication_routes_are_explicit_and_legacy_cannot_write_option1() {
    let mut env = environment();
    let request = publication_candidates::request(&env).unwrap();
    assert_eq!(request.release_route, "option1");
    let mut raw: Value = serde_json::from_str(&env["RELEASE_REQUEST"]).unwrap();
    raw["release_route"] = json!("legacy-acceptance");
    env.insert("RELEASE_REQUEST".into(), raw.to_string());
    assert!(publication_candidates::request(&env).is_err());
    assert_eq!(
        omni_release_launcher::input::Request::parse(&raw.to_string())
            .unwrap()
            .release_route,
        "legacy-acceptance"
    );
    raw["build_only"] = json!(true);
    raw["ios_action"] = json!("skip");
    assert!(omni_release_launcher::input::Request::parse(&raw.to_string()).is_err());
    for invalid in [json!("legacy"), json!(true), json!(null)] {
        raw["release_route"] = invalid;
        assert!(omni_release_launcher::input::Request::parse(&raw.to_string()).is_err());
    }
}
