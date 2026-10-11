//! Loopback HTTP regressions for the active private staging publisher.
//! All identities, packages and API responses are synthetic. No real token or
//! provider client is used; the listener and adapter accept only 127.0.0.1.
use omni_release_launcher::{
    Environment, Result,
    publication_candidates::{self, Plan, Publication, ReleaseApi, STAGING_REPOSITORY},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

fn environment() -> Environment {
    Environment::from([
        ("GITHUB_ACTIONS".into(), "true".into()),
        ("GITHUB_EVENT_NAME".into(), "workflow_dispatch".into()),
        ("GITHUB_REPOSITORY".into(), "omnisolo-llc/omniterm-release".into()),
        ("GITHUB_REF".into(), "refs/heads/main".into()),
        ("GITHUB_WORKFLOW_REF".into(), "omnisolo-llc/omniterm-release/.github/workflows/release.yml@refs/heads/main".into()),
        ("GITHUB_SHA".into(), "b".repeat(40)),
        ("GITHUB_RUN_ID".into(), "42".into()),
        ("GITHUB_RUN_ATTEMPT".into(), "2".into()),
        ("SOURCE_REPOSITORY".into(), "omnisolo-llc/omniterm".into()),
        ("SOURCE_BRANCH".into(), "main".into()),
        ("RELEASE_TARGET".into(), "publish".into()),
        ("RESOLVED_SOURCE_SHA".into(), "a".repeat(40)),
        ("RELEASE_REQUEST".into(), json!({"source_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"version":"1.2.3","build_number":"42","build_only":false,"ios_action":"submit"}).to_string()),
    ])
}

fn candidate() -> (tempfile::TempDir, Plan) {
    candidate_for(&environment())
}

fn candidate_for(env: &Environment) -> (tempfile::TempDir, Plan) {
    candidate_with_names(env, &["omniterm-1.2.3-linux-x64.tar.gz", "SHA256SUMS"])
}

fn candidate_with_names(env: &Environment, names: &[&str]) -> (tempfile::TempDir, Plan) {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let request = publication_candidates::request(env).unwrap();
    let mut files = serde_json::Map::new();
    for name in names {
        let bytes = format!("synthetic archive bytes for {name}\n").into_bytes();
        fs::write(directory.path().join(name), &bytes).unwrap();
        files.insert((*name).into(), json!({"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes)),"content_type":"application/octet-stream"}));
    }
    let document = json!({"schema":1,"identity":publication_candidates::identity(env).unwrap(),"release":serde_json::from_str::<Value>(&request.normalized().unwrap()).unwrap(),"repository":"omnisolo-llc/omniterm-release","files":files});
    let plan = publication_candidates::read_plan(&document, env, directory.path()).unwrap();
    (directory, plan)
}

fn release(plan: &Plan, draft: bool) -> Value {
    json!({"id":7,"tag_name":"v1.2.3","name":"Omniterm v1.2.3","draft":draft,"prerelease":false,"target_commitish":"a".repeat(40),"body":plan.notes()})
}

#[derive(Clone)]
struct Asset {
    metadata: Value,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Default)]
enum Failure {
    #[default]
    None,
    Before,
    After,
}

struct State {
    repository: Value,
    membership_actor: Option<String>,
    membership: Value,
    release: Option<Value>,
    assets: BTreeMap<u64, Asset>,
    requests: Vec<Value>,
    create_failure: Failure,
    upload_failure: Failure,
    promote_failure: Failure,
    metadata_mutation: Option<(String, Value)>,
    promotion_mutation: Option<(String, Value)>,
    upload_mutation: Option<(String, Value)>,
    release_inventory: Option<Value>,
    asset_inventory: Option<Value>,
    create_mutation: Option<(String, Value)>,
    replace_asset_after_download: bool,
    promotion_readback_mutation: Option<(String, Value)>,
    release_pages: BTreeMap<u32, Value>,
    download_denial: bool,
    repository_reads: u64,
    repository_mutation: Option<(u64, Value)>,
    expected_assets: usize,
    upload_seen: bool,
    post_upload_readbacks: BTreeSet<u64>,
    metadata_after_uploaded_readback: Option<(String, Value)>,
    drift_request: Option<usize>,
    upload_asset_mutation: Option<&'static str>,
    promotion_asset_mutation: Option<&'static str>,
    denied_reads: BTreeMap<String, usize>,
    upload_read_denial: Option<String>,
    create_read_denial: Option<String>,
}

impl State {
    fn new(plan: &Plan, directory: &Path, draft: bool) -> Self {
        let assets = plan.files().iter().enumerate().map(|(index, (name, record))| {
            let id = 11 + index as u64;
            (id, Asset {metadata:json!({"id":id,"name":name,"state":"uploaded","size":record.bytes}),bytes:fs::read(directory.join(name)).unwrap()})
        }).collect();
        Self {
            repository: json!({"full_name":STAGING_REPOSITORY,"private":true}),
            membership_actor: std::env::var("GITHUB_ACTOR")
                .ok()
                .map(|actor| actor.trim().to_owned())
                .filter(|actor| !actor.is_empty()),
            membership: json!({"state":"active"}),
            release: Some(release(plan, draft)),
            assets,
            requests: Vec::new(),
            create_failure: Failure::None,
            upload_failure: Failure::None,
            promote_failure: Failure::None,
            metadata_mutation: None,
            promotion_mutation: None,
            upload_mutation: None,
            release_inventory: None,
            asset_inventory: None,
            create_mutation: None,
            replace_asset_after_download: false,
            promotion_readback_mutation: None,
            release_pages: BTreeMap::new(),
            download_denial: false,
            repository_reads: 0,
            repository_mutation: None,
            expected_assets: plan.files().len(),
            upload_seen: false,
            post_upload_readbacks: BTreeSet::new(),
            metadata_after_uploaded_readback: None,
            drift_request: None,
            upload_asset_mutation: None,
            promotion_asset_mutation: None,
            denied_reads: BTreeMap::new(),
            upload_read_denial: None,
            create_read_denial: None,
        }
    }

    fn retained(&self) -> Value {
        json!({"release":self.release,"assets":self.assets.iter().map(|(id,asset)|json!({"id":id,"metadata":asset.metadata,"bytes":asset.bytes})).collect::<Vec<_>>()})
    }

    fn mutate_assets(&mut self, scenario: &str) {
        match scenario {
            "tamper" => self.assets.last_entry().unwrap().get_mut().bytes[0] ^= 1,
            "starter" => {
                self.assets.last_entry().unwrap().get_mut().metadata["state"] = json!("starter");
            }
            "missing" => {
                self.assets.pop_last();
            }
            "replace" | "replace-first" => {
                let (_, mut asset) = if scenario == "replace-first" {
                    self.assets.pop_first().unwrap()
                } else {
                    self.assets.pop_last().unwrap()
                };
                asset.metadata["id"] = json!(99);
                self.assets.insert(99, asset);
            }
            "duplicate-name" | "duplicate-id" => {
                let mut asset = self.assets.last_key_value().unwrap().1.clone();
                if scenario == "duplicate-name" {
                    asset.metadata["id"] = json!(99);
                }
                self.assets.insert(99, asset);
            }
            "extra" => {
                self.assets.insert(99, Asset {metadata:json!({"id":99,"name":"ios-private.ipa","state":"uploaded","size":7}),bytes:b"private".to_vec()});
            }
            _ => panic!("Unknown synthetic asset mutation: {scenario}"),
        }
    }

    fn deny_next_read(&mut self, endpoint: String) {
        let next = self
            .requests
            .iter()
            .filter(|request| request["method"] == "GET" && request["endpoint"] == endpoint)
            .count()
            + 1;
        self.denied_reads.insert(endpoint, next);
    }

    fn handle(&mut self, method: &str, endpoint: &str, bytes: &[u8]) -> (u16, Vec<u8>) {
        let prefix = format!("repos/{STAGING_REPOSITORY}");
        if method == "GET"
            && self.denied_reads.get(endpoint).is_some_and(|at| {
                self.requests
                    .iter()
                    .filter(|request| request["method"] == "GET" && request["endpoint"] == endpoint)
                    .count()
                    == *at
            })
        {
            return (403, b"sentinel denied readback".to_vec());
        }
        let value = if method == "GET" && endpoint == prefix {
            self.repository_reads += 1;
            if self
                .repository_mutation
                .as_ref()
                .is_some_and(|(at, _)| *at == self.repository_reads)
            {
                self.repository = self.repository_mutation.take().unwrap().1;
            }
            self.repository.clone()
        } else if method == "GET"
            && self.membership_actor.as_ref().is_some_and(|actor| {
                endpoint == format!("orgs/omnisolo-llc/teams/release-eng/memberships/{actor}")
            })
        {
            // This fixture supplies a controlled synthetic team response for
            // the exact actor being exercised. Other actors/teams stay denied.
            self.membership.clone()
        } else if method == "GET" && endpoint.starts_with(&format!("{prefix}/releases?")) {
            let page = endpoint
                .split('&')
                .find_map(|field| field.strip_prefix("page="))
                .unwrap()
                .parse::<u32>()
                .unwrap();
            self.release_pages
                .get(&page)
                .cloned()
                .or_else(|| self.release_inventory.clone())
                .unwrap_or_else(|| json!(self.release.iter().collect::<Vec<_>>()))
        } else if method == "GET" && endpoint == format!("{prefix}/releases/7") {
            if let Some((key, value)) = self.metadata_mutation.take() {
                self.release.as_mut().unwrap()[key] = value;
            }
            self.release.clone().unwrap_or(json!({"status":404}))
        } else if method == "GET" && endpoint == format!("{prefix}/releases/7/assets?per_page=100")
        {
            self.asset_inventory.clone().unwrap_or_else(|| {
                json!(
                    self.assets
                        .values()
                        .map(|asset| &asset.metadata)
                        .collect::<Vec<_>>()
                )
            })
        } else if let Some(id) = endpoint.strip_prefix(&format!("{prefix}/releases/assets/")) {
            let id = id.parse::<u64>().unwrap();
            match method {
                "GET" => {
                    if self.download_denial {
                        return (403, b"denied synthetic asset readback".to_vec());
                    }
                    let Some(asset) = self.assets.get(&id) else {
                        return (404, b"missing synthetic asset".to_vec());
                    };
                    let bytes = asset.bytes.clone();
                    if self.upload_seen {
                        self.post_upload_readbacks.insert(id);
                    }
                    if self.metadata_after_uploaded_readback.is_some()
                        && self.assets.len() == self.expected_assets
                        && self.post_upload_readbacks.len() == self.expected_assets
                    {
                        let (key, value) = self.metadata_after_uploaded_readback.take().unwrap();
                        self.release.as_mut().unwrap()[key] = value;
                        self.drift_request = Some(self.requests.len() - 1);
                    }
                    if std::mem::take(&mut self.replace_asset_after_download) {
                        let mut replacement = self.assets.remove(&id).unwrap();
                        replacement.metadata["id"] = json!(99);
                        self.assets.insert(99, replacement);
                    }
                    return (200, bytes);
                }
                "DELETE" => {
                    self.assets.remove(&id);
                    json!({})
                }
                _ => json!({"status":400}),
            }
        } else if method == "POST" && endpoint == format!("{prefix}/releases") {
            if matches!(self.create_failure, Failure::Before) {
                return (502, b"synthetic create failure".to_vec());
            }
            let mut value: Value = serde_json::from_slice(bytes).unwrap();
            value["id"] = json!(7);
            if let Some((key, field)) = self.create_mutation.take() {
                value[key] = field;
            }
            self.release = Some(value.clone());
            if let Some(endpoint) = self.create_read_denial.take() {
                self.deny_next_read(endpoint);
            }
            if matches!(self.create_failure, Failure::After) {
                return (502, b"synthetic uncertain create".to_vec());
            }
            value
        } else if method == "POST"
            && endpoint.starts_with(&format!("{prefix}/releases/7/assets?name="))
        {
            let failure = std::mem::take(&mut self.upload_failure);
            if matches!(failure, Failure::Before) {
                return (502, b"synthetic upload failure".to_vec());
            }
            let name = endpoint.split_once("?name=").unwrap().1;
            if self
                .assets
                .values()
                .any(|asset| asset.metadata["name"] == name)
            {
                return (422, b"synthetic duplicate upload".to_vec());
            }
            let id = self.assets.last_key_value().map_or(11, |(id, _)| id + 1);
            let metadata = json!({"id":id,"name":name,"state":"uploaded","size":bytes.len()});
            self.assets.insert(
                id,
                Asset {
                    metadata: metadata.clone(),
                    bytes: bytes.to_vec(),
                },
            );
            self.upload_seen = true;
            self.post_upload_readbacks.clear();
            if let Some((key, value)) = self.upload_mutation.take() {
                self.release.as_mut().unwrap()[key] = value;
            }
            if let Some(scenario) = self.upload_asset_mutation.take() {
                self.mutate_assets(scenario);
            }
            if let Some(endpoint) = self.upload_read_denial.take() {
                self.deny_next_read(endpoint);
            }
            if matches!(failure, Failure::After) {
                return (502, b"synthetic uncertain upload".to_vec());
            }
            metadata
        } else if method == "PATCH" && endpoint == format!("{prefix}/releases/7") {
            if matches!(self.promote_failure, Failure::Before) {
                return (502, b"synthetic promotion failure".to_vec());
            }
            let patch: Value = serde_json::from_slice(bytes).unwrap();
            let value = self.release.as_mut().unwrap();
            for (key, field) in patch.as_object().unwrap() {
                value[key] = field.clone();
            }
            if patch["draft"] == false
                && let Some((key, field)) = self.promotion_mutation.take()
            {
                value[&key] = field;
            }
            let response = value.clone();
            if patch["draft"] == false
                && let Some((key, field)) = self.promotion_readback_mutation.take()
            {
                value[key] = field;
            }
            if let Some(scenario) = self.promotion_asset_mutation.take() {
                self.mutate_assets(scenario);
            }
            if matches!(self.promote_failure, Failure::After) {
                return (502, b"synthetic uncertain promotion".to_vec());
            }
            response
        } else {
            json!({"status":404})
        };
        let status = value["status"].as_u64().unwrap_or(200) as u16;
        (status, serde_json::to_vec(&value).unwrap())
    }
}

struct HttpFixture {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    label: String,
    original: Value,
}

impl HttpFixture {
    fn start(label: impl Into<String>, state: State) -> Self {
        let original = state.retained();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback());
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(state));
        let observed = state.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let join = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let (mut socket, peer) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("Loopback fixture accept failed: {error}"),
                };
                assert!(peer.ip().is_loopback());
                // Accepted sockets can inherit nonblocking mode on BSD/macOS.
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 8192);
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                let mut first = header.lines().next().unwrap().split_whitespace();
                let method = first.next().unwrap();
                let endpoint = first.next().unwrap().strip_prefix('/').unwrap();
                let length = header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                assert!(length < 65536);
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                let (status, reply) = {
                    let mut state = observed.lock().unwrap();
                    let index = state.requests.len();
                    state.requests.push(json!({"method":method,"endpoint":endpoint,"request_bytes":body.len(),"request_sha256":format!("{:x}",Sha256::digest(&body)),"request_json":serde_json::from_slice::<Value>(&body).ok()}));
                    let (status, reply) = state.handle(method, endpoint, &body);
                    let request = &mut state.requests[index];
                    request["response_status"] = json!(status);
                    request["response_bytes"] = json!(reply.len());
                    request["response_sha256"] = json!(format!("{:x}", Sha256::digest(&reply)));
                    request["response_json"] = json!(serde_json::from_slice::<Value>(&reply).ok());
                    (status, reply)
                };
                write!(socket,"HTTP/1.1 {status} Synthetic\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.len()).unwrap();
                socket.write_all(&reply).unwrap();
            }
        });
        Self {
            address,
            state,
            stop,
            join: Some(join),
            label: label.into(),
            original,
        }
    }

    fn exchange(&self, method: &str, endpoint: &str, body: &[u8]) -> Result<Vec<u8>> {
        assert!(self.address.ip().is_loopback());
        let mut socket = TcpStream::connect(self.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(socket,"{method} /{endpoint} HTTP/1.1\r\nHost: loopback-synthetic\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
        socket.write_all(body).unwrap();
        let mut raw = Vec::new();
        socket.read_to_end(&mut raw).unwrap();
        let start = raw.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
        let header = std::str::from_utf8(&raw[..start]).unwrap();
        let status = header
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        if status != 200 {
            return Err(match raw[start..].as_ref() {
                b"synthetic create failure" | b"synthetic uncertain create" => {
                    "Sentinel create HTTP failure"
                }
                b"synthetic upload failure" | b"synthetic uncertain upload" => {
                    "Sentinel upload HTTP failure"
                }
                b"synthetic promotion failure" | b"synthetic uncertain promotion" => {
                    "Sentinel promotion HTTP failure"
                }
                _ => "Sentinel readback HTTP failure",
            });
        }
        Ok(raw[start..].to_vec())
    }

    fn writes(&self) -> Vec<Value> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|request| request["method"] != "GET")
            .cloned()
            .collect()
    }

    fn assert_preserved(&self, original: &Value) {
        assert_eq!(&self.state.lock().unwrap().retained(), original);
        assert!(self.writes().is_empty());
    }
}

impl ReleaseApi for HttpFixture {
    fn get_json(&mut self, endpoint: &str) -> Result<Value> {
        serde_json::from_slice(&self.exchange("GET", endpoint, &[])?)
            .map_err(|_| "Synthetic JSON failure")
    }
    fn write_json(&mut self, method: &str, endpoint: &str, body: &Value) -> Result<Value> {
        serde_json::from_slice(&self.exchange(
            method,
            endpoint,
            &serde_json::to_vec(body).unwrap(),
        )?)
        .map_err(|_| "Synthetic JSON failure")
    }
    fn upload(&mut self, id: u64, name: &str, path: &Path) -> Result<Value> {
        serde_json::from_slice(&self.exchange(
            "POST",
            &format!("repos/{STAGING_REPOSITORY}/releases/{id}/assets?name={name}"),
            &fs::read(path).unwrap(),
        )?)
        .map_err(|_| "Synthetic JSON failure")
    }
    fn download(&mut self, id: u64, output: &Path) -> Result<()> {
        fs::write(
            output,
            self.exchange(
                "GET",
                &format!("repos/{STAGING_REPOSITORY}/releases/assets/{id}"),
                &[],
            )?,
        )
        .map_err(|_| "Synthetic readback failure")
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let server_failed = self.join.take().unwrap().join().is_err();
        if let Ok(directory) = std::env::var("OMNI_PRIVATE_STAGING_EVIDENCE") {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let evidence = json!({"schema":1,"scope":"synthetic loopback HTTP only","label":self.label,"server_failed":server_failed,"drift_request":state.drift_request,"original":self.original,"requests":state.requests,"final_release":state.release,"final_assets":state.assets.values().map(|asset|json!({"metadata":asset.metadata,"sha256":format!("{:x}",Sha256::digest(&asset.bytes))})).collect::<Vec<_>>()});
            fs::write(
                Path::new(&directory).join(format!("{}.json", self.label)),
                serde_json::to_vec_pretty(&evidence).unwrap(),
            )
            .unwrap();
        }
        if !thread::panicking() {
            assert!(!server_failed, "Synthetic HTTP server failed");
        }
    }
}

fn exact_readback_after(state: &State, plan: &Plan, after: usize, draft: bool) {
    let before_next_write = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| *index > after && request["method"] != "GET")
        .map_or(state.requests.len(), |(index, _)| index);
    let metadata = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| {
            *index > after
                && *index < before_next_write
                && request["method"] == "GET"
                && request["endpoint"] == format!("repos/{STAGING_REPOSITORY}/releases/7")
        })
        .unwrap()
        .0;
    let response = &state.requests[metadata]["response_json"];
    assert_eq!(state.requests[metadata]["response_status"], 200);
    for (field, expected) in release(plan, draft).as_object().unwrap() {
        assert_eq!(&response[field], expected, "Readback field {field}");
    }
    let inventory = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| {
            *index > metadata
                && *index < before_next_write
                && request["method"] == "GET"
                && request["endpoint"]
                    == format!("repos/{STAGING_REPOSITORY}/releases/7/assets?per_page=100")
        })
        .unwrap()
        .0;
    assert_eq!(state.requests[inventory]["response_status"], 200);
    let rows = state.requests[inventory]["response_json"]
        .as_array()
        .unwrap();
    assert_eq!(rows.len(), plan.files().len());
    for (name, record) in plan.files() {
        let asset = rows.iter().find(|asset| asset["name"] == *name).unwrap();
        assert_eq!(asset["size"], record.bytes);
        assert_eq!(asset["state"], "uploaded");
        let id = asset["id"].as_u64().unwrap();
        let readback = state
            .requests
            .iter()
            .enumerate()
            .find(|(index, request)| {
                *index > inventory
                    && *index < before_next_write
                    && request["method"] == "GET"
                    && request["endpoint"]
                        == format!("repos/{STAGING_REPOSITORY}/releases/assets/{id}")
            })
            .unwrap()
            .1;
        assert_eq!(readback["response_status"], 200);
        assert_eq!(readback["response_bytes"], record.bytes);
        assert_eq!(readback["response_sha256"], record.sha256);
    }
}

fn every_write_has_fresh_authority(state: &State, plan: &Plan) {
    let mut previous = 0;
    for (index, request) in state.requests.iter().enumerate() {
        if request["method"] == "GET" {
            continue;
        }
        let guards = &state.requests[previous..index];
        assert!(
            guards.iter().any(|guard| guard["method"] == "GET"
                && guard["endpoint"] == format!("repos/{STAGING_REPOSITORY}")
                && guard["response_status"] == 200
                && guard["response_json"]
                    == json!({"full_name":STAGING_REPOSITORY,"private":true})),
            "Write lacks fresh private repository authority: {request}"
        );
        if request["endpoint"] != format!("repos/{STAGING_REPOSITORY}/releases") {
            assert!(
                guards.iter().any(|guard| guard["method"] == "GET"
                    && guard["endpoint"] == format!("repos/{STAGING_REPOSITORY}/releases/7")
                    && guard["response_status"] == 200
                    && guard["response_json"] == release(plan, true)),
                "Write lacks fresh owned draft authority: {request}"
            );
        }
        previous = index + 1;
    }
}

#[test]
fn a_conflicting_published_private_archive_is_immutable() {
    let (directory, plan) = candidate();
    let mut state = State::new(&plan, directory.path(), false);
    state.release.as_mut().unwrap()["target_commitish"] = json!("c".repeat(40));
    let original = state
        .assets
        .iter()
        .map(|(id, asset)| (*id, asset.bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut fixture = HttpFixture::start("conflicting-published-source", state);
    let result = publication_candidates::publish_to_staging(&plan, &mut fixture);
    assert!(
        fixture.writes().is_empty(),
        "Conflicting published archive received writes: {:?}",
        fixture.writes()
    );
    assert_eq!(
        result,
        Err("Staging release source differs from reviewed identity")
    );
    assert_eq!(
        fixture
            .state
            .lock()
            .unwrap()
            .assets
            .iter()
            .map(|(id, asset)| (*id, asset.bytes.clone()))
            .collect::<BTreeMap<_, _>>(),
        original
    );
    fixture.assert_preserved(&fixture.original);
}

#[test]
fn a_matching_published_private_archive_is_reused_after_exact_byte_readbacks() {
    let (directory, plan) = candidate();
    let state = State::new(&plan, directory.path(), false);
    let original = state.assets.keys().copied().collect::<Vec<_>>();
    let mut fixture = HttpFixture::start("identical-published", state);
    assert_eq!(
        publication_candidates::publish_to_staging(&plan, &mut fixture),
        Ok(Publication::AlreadyPublished)
    );
    assert!(fixture.writes().is_empty());
    fixture.assert_preserved(&fixture.original);
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.assets.keys().copied().collect::<Vec<_>>(), original);
    for id in original {
        assert!(
            state
                .requests
                .iter()
                .any(|request| request["method"] == "GET"
                    && request["response_status"] == 200
                    && request["endpoint"]
                        == format!("repos/{STAGING_REPOSITORY}/releases/assets/{id}"))
        );
    }
    exact_readback_after(&state, &plan, 0, false);
}

#[test]
fn private_identity_conflicts_preserve_both_drafts_and_published_archives() {
    for draft in [false, true] {
        for (field, changed, error) in [
            (
                "target_commitish",
                json!("c".repeat(40)),
                "Staging release source differs from reviewed identity",
            ),
            (
                "body",
                json!("different builder, run, attempt, proof or file inventory"),
                "Staging release plan differs from reviewed identity",
            ),
            (
                "prerelease",
                json!(true),
                "Staging release prerelease state differs from reviewed identity",
            ),
            ("draft", json!(null), "Missing release state"),
        ] {
            let (directory, plan) = candidate();
            let mut state = State::new(&plan, directory.path(), draft);
            state.release.as_mut().unwrap()[field] = changed;
            let mut fixture =
                HttpFixture::start(format!("identity-conflict-{field}-{draft}"), state);
            assert_eq!(
                publication_candidates::publish_to_staging(&plan, &mut fixture),
                Err(error),
                "conflict field {field}, draft {draft}"
            );
            assert!(fixture.writes().is_empty());
            fixture.assert_preserved(&fixture.original);
        }
    }
}

#[test]
fn published_private_inventory_tamper_missing_or_unreviewed_assets_never_write() {
    for scenario in ["tamper", "missing", "unreviewed", "starter", "duplicate"] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), false);
        match scenario {
            "tamper" => state.assets.first_entry().unwrap().get_mut().bytes[0] ^= 1,
            "missing" => {
                state.assets.pop_last();
            }
            "unreviewed" => {
                state.assets.insert(99, Asset {metadata:json!({"id":99,"name":"omniterm-1.2.3-ios-private.ipa","state":"uploaded","size":7}),bytes:b"private".to_vec()});
            }
            "starter" => {
                state.assets.first_entry().unwrap().get_mut().metadata["state"] = json!("starter")
            }
            "duplicate" => {
                let mut asset = state.assets.first_key_value().unwrap().1.clone();
                asset.metadata["id"] = json!(99);
                state.assets.insert(99, asset);
            }
            _ => unreachable!(),
        }
        let mut fixture = HttpFixture::start(format!("published-inventory-{scenario}"), state);
        assert!(publication_candidates::publish_to_staging(&plan, &mut fixture).is_err());
        assert!(fixture.writes().is_empty(), "scenario {scenario}");
        fixture.assert_preserved(&fixture.original);
    }
}

#[test]
fn an_owned_private_draft_uploads_only_missing_files_and_preserves_original_assets() {
    let (directory, plan) = candidate();
    let mut state = State::new(&plan, directory.path(), true);
    let missing = state.assets.pop_last().unwrap().1.metadata["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let original = state.assets.first_key_value().unwrap().0.to_owned();
    let original_bytes = state.assets[&original].bytes.clone();
    let mut fixture = HttpFixture::start("owned-draft-missing-file", state);
    assert_eq!(
        publication_candidates::publish_to_staging(&plan, &mut fixture),
        Ok(Publication::Published)
    );
    let writes = fixture.writes();
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0]["method"], "POST");
    assert_eq!(
        writes[0]["endpoint"],
        format!("repos/{STAGING_REPOSITORY}/releases/7/assets?name={missing}")
    );
    assert_eq!(
        writes[1]["request_json"],
        json!({"draft":false,"make_latest":"true"})
    );
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.assets[&original].bytes, original_bytes);
    assert_eq!(state.assets.len(), plan.files().len());
    assert_eq!(state.release.as_ref().unwrap()["draft"], false);
    every_write_has_fresh_authority(&state, &plan);
    let promoted = state
        .requests
        .iter()
        .position(|request| request["method"] == "PATCH")
        .unwrap();
    exact_readback_after(&state, &plan, promoted, false);
}

#[test]
fn a_changed_owned_draft_is_detected_before_any_upload_or_promotion() {
    let (directory, plan) = candidate();
    let mut state = State::new(&plan, directory.path(), true);
    state.assets.pop_last();
    state.metadata_mutation = Some(("body".into(), json!("a different attempt took custody")));
    let mut fixture = HttpFixture::start("changed-draft-before-write", state);
    assert_eq!(
        publication_candidates::publish_to_staging(&plan, &mut fixture),
        Err("Staging release plan differs from reviewed identity")
    );
    assert!(fixture.writes().is_empty());
}

#[test]
fn an_uncertain_private_upload_is_adopted_only_after_owned_draft_and_byte_readbacks() {
    let (directory, plan) = candidate();
    let mut state = State::new(&plan, directory.path(), true);
    state.assets.pop_last();
    let (original_id, original_asset) = state.assets.first_key_value().unwrap();
    let original_id = *original_id;
    let original_bytes = original_asset.bytes.clone();
    state.upload_failure = Failure::After;
    let mut fixture = HttpFixture::start("uncertain-upload-stored", state);
    assert_eq!(
        publication_candidates::publish_to_staging(&plan, &mut fixture),
        Ok(Publication::Published)
    );
    let writes = fixture.writes();
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[1]["method"], "PATCH");
    assert_eq!(
        writes
            .iter()
            .filter(|request| request["method"] == "POST")
            .count(),
        1
    );
    assert_eq!(
        writes
            .iter()
            .filter(|request| request["method"] == "DELETE")
            .count(),
        0
    );
    assert_eq!(
        fixture.state.lock().unwrap().assets.len(),
        plan.files().len()
    );
    let state = fixture.state.lock().unwrap();
    every_write_has_fresh_authority(&state, &plan);
    assert_eq!(state.assets[&original_id].bytes, original_bytes);
    let uploaded = state
        .requests
        .iter()
        .position(|request| request["method"] == "POST" && request["response_status"] == 502)
        .unwrap();
    let owned = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| {
            *index > uploaded
                && request["method"] == "GET"
                && request["endpoint"] == format!("repos/{STAGING_REPOSITORY}/releases/7")
        })
        .unwrap()
        .0;
    assert_eq!(state.requests[owned]["response_json"]["id"], 7);
    assert_eq!(state.requests[owned]["response_json"]["draft"], true);
    assert_eq!(state.requests[owned]["response_json"]["body"], plan.notes());
    let inventory = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| {
            *index > owned
                && request["endpoint"]
                    == format!("repos/{STAGING_REPOSITORY}/releases/7/assets?per_page=100")
        })
        .unwrap()
        .0;
    let recovered_id = *state.assets.keys().find(|id| **id != original_id).unwrap();
    let downloaded = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| {
            *index > inventory
                && request["endpoint"]
                    == format!("repos/{STAGING_REPOSITORY}/releases/assets/{recovered_id}")
        })
        .unwrap()
        .0;
    assert_eq!(
        state.requests[downloaded]["response_sha256"],
        format!("{:x}", Sha256::digest(&state.assets[&recovered_id].bytes))
    );
    let promoted = state
        .requests
        .iter()
        .position(|request| request["method"] == "PATCH")
        .unwrap();
    assert!(downloaded < promoted);
    exact_readback_after(&state, &plan, uploaded, true);
    exact_readback_after(&state, &plan, promoted, false);
}

#[test]
fn a_failed_private_upload_without_a_readback_never_blindly_retries() {
    let (directory, plan) = candidate();
    let mut state = State::new(&plan, directory.path(), true);
    state.assets.pop_last();
    state.upload_failure = Failure::Before;
    let mut fixture = HttpFixture::start("uncertain-upload-missing", state);
    assert_eq!(
        publication_candidates::publish_to_staging(&plan, &mut fixture),
        Err("Sentinel upload HTTP failure")
    );
    assert_eq!(fixture.writes().len(), 1);
    assert_eq!(
        fixture.state.lock().unwrap().release.as_ref().unwrap()["draft"],
        true
    );
    assert_eq!(
        publication_candidates::publish_to_staging(&plan, &mut fixture),
        Ok(Publication::Published)
    );
    assert!(
        fixture
            .writes()
            .iter()
            .all(|request| request["method"] != "DELETE")
    );
}

#[test]
fn an_uncertain_upload_never_adopts_a_changed_or_published_release() {
    for (field, value) in [
        ("body", json!("different release owner")),
        ("draft", json!(false)),
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        state.assets.pop_last();
        state.upload_failure = Failure::After;
        state.upload_mutation = Some((field.into(), value));
        let mut fixture = HttpFixture::start(format!("uncertain-upload-foreign-{field}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err("Sentinel upload HTTP failure")
        );
        assert_eq!(fixture.writes().len(), 1);
    }
}

#[test]
fn an_uncertain_create_only_adopts_an_exact_owned_draft() {
    let (directory, plan) = candidate();
    let mut state = State::new(&plan, directory.path(), true);
    state.release = None;
    state.assets.clear();
    state.create_failure = Failure::After;
    let mut fixture = HttpFixture::start("uncertain-create-owned-draft", state);
    assert_eq!(
        publication_candidates::publish_to_staging(&plan, &mut fixture),
        Ok(Publication::Published)
    );
    assert_eq!(
        fixture
            .writes()
            .iter()
            .filter(|request| request["endpoint"] == format!("repos/{STAGING_REPOSITORY}/releases"))
            .count(),
        1
    );
    assert_eq!(
        fixture.state.lock().unwrap().assets.len(),
        plan.files().len()
    );
    let state = fixture.state.lock().unwrap();
    every_write_has_fresh_authority(&state, &plan);
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|request| request["method"] == "PATCH")
            .count(),
        1
    );
    let created = state
        .requests
        .iter()
        .position(|request| request["method"] == "POST" && request["response_status"] == 502)
        .unwrap();
    let enumerated = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| {
            *index > created
                && request["endpoint"]
                    == format!("repos/{STAGING_REPOSITORY}/releases?per_page=100&page=1")
        })
        .unwrap()
        .0;
    let owned = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| {
            *index > enumerated
                && request["endpoint"] == format!("repos/{STAGING_REPOSITORY}/releases/7")
        })
        .unwrap()
        .0;
    assert_eq!(state.requests[owned]["response_json"]["id"], 7);
    assert_eq!(state.requests[owned]["response_json"]["draft"], true);
    assert_eq!(state.requests[owned]["response_json"]["body"], plan.notes());
    let uploaded = state
        .requests
        .iter()
        .enumerate()
        .find(|(index, request)| *index > created && request["method"] == "POST")
        .unwrap()
        .0;
    assert!(owned < uploaded);
}

#[test]
fn private_repository_denial_or_public_visibility_never_authorize_a_write() {
    for (label, repository) in [
        ("private-api-denial", json!({"status":403})),
        (
            "private-public-visibility",
            json!({"full_name":STAGING_REPOSITORY,"private":false}),
        ),
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        state.repository = repository;
        let mut fixture = HttpFixture::start(label, state);
        assert!(publication_candidates::publish_to_staging(&plan, &mut fixture).is_err());
        assert!(fixture.writes().is_empty());
    }
}

#[test]
fn private_promotion_must_preserve_the_exact_release_identity() {
    let (directory, plan) = candidate();
    let mut state = State::new(&plan, directory.path(), true);
    state.promotion_mutation = Some(("body".into(), json!("unexpected promotion identity")));
    let mut fixture = HttpFixture::start("promotion-changed-identity", state);
    assert!(publication_candidates::publish_to_staging(&plan, &mut fixture).is_err());
    assert_eq!(fixture.writes().len(), 1);
}

#[test]
fn another_build_run_or_attempt_cannot_replace_same_version_private_bytes() {
    let (directory, plan) = candidate();
    for field in [
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SHA",
        "build_number",
    ] {
        let mut env = environment();
        if field == "build_number" || field == "GITHUB_SHA" {
            let mut request: Value = serde_json::from_str(&env["RELEASE_REQUEST"]).unwrap();
            if field == "GITHUB_SHA" {
                env.insert(field.into(), "c".repeat(40));
                request["builder_sha"] = json!("c".repeat(40));
            } else {
                request[field] = json!("43");
            }
            env.insert("RELEASE_REQUEST".into(), request.to_string());
        } else {
            env.insert(field.into(), "3".into());
        }
        let (_other_directory, other) = candidate_for(&env);
        assert_ne!(plan.notes(), other.notes());
        for draft in [false, true] {
            let mut state = State::new(&plan, directory.path(), draft);
            state.release.as_mut().unwrap()["body"] = json!(other.notes());
            let mut fixture =
                HttpFixture::start(format!("different-identity-{field}-{draft}"), state);
            assert_eq!(
                publication_candidates::publish_to_staging(&plan, &mut fixture),
                Err("Staging release plan differs from reviewed identity")
            );
            assert!(fixture.writes().is_empty());
            fixture.assert_preserved(&fixture.original);
        }
    }
}

#[test]
fn incomplete_or_duplicate_private_inventories_cannot_authorize_writes() {
    for scenario in [
        "full-page",
        "duplicate-tag",
        "duplicate-id",
        "invalid-inventory",
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        match scenario {
            "full-page" => {
                let asset = state.assets.first_key_value().unwrap().1.metadata.clone();
                state.asset_inventory = Some(json!(vec![asset; 100]));
            }
            "duplicate-tag" => {
                let original = state.release.as_ref().unwrap().clone();
                let mut second = original.clone();
                second["id"] = json!(8);
                state.release_inventory = Some(json!([original, second]));
            }
            "duplicate-id" => {
                let original = state.release.as_ref().unwrap().clone();
                state.release_inventory = Some(json!([original, original]));
            }
            "invalid-inventory" => {
                state.release_inventory = Some(json!({"status":"not an inventory"}))
            }
            _ => unreachable!(),
        }
        let mut fixture = HttpFixture::start(format!("invalid-inventory-{scenario}"), state);
        assert!(publication_candidates::publish_to_staging(&plan, &mut fixture).is_err());
        assert!(fixture.writes().is_empty());
        fixture.assert_preserved(&fixture.original);
    }
}

#[test]
fn an_uncertain_private_create_never_retries_or_adopts_foreign_state() {
    for (label, failure, mutation) in [
        ("create-unverified-absence", Failure::Before, None),
        (
            "create-unverified-owner",
            Failure::After,
            Some(("body".into(), json!("foreign release identity"))),
        ),
        (
            "create-unverified-publication",
            Failure::After,
            Some(("draft".into(), json!(false))),
        ),
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        state.release = None;
        state.assets.clear();
        state.create_failure = failure;
        state.create_mutation = mutation;
        let mut fixture = HttpFixture::start(label, state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err("Sentinel create HTTP failure")
        );
        assert_eq!(fixture.writes().len(), 1);
        assert!(fixture.state.lock().unwrap().assets.is_empty());
    }
}

#[test]
fn a_replaced_private_asset_id_is_detected_before_upload_or_promotion() {
    for draft in [false, true] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), draft);
        if draft {
            state.assets.pop_last();
        }
        state.replace_asset_after_download = true;
        let mut fixture = HttpFixture::start(format!("retained-asset-replaced-{draft}"), state);
        assert!(publication_candidates::publish_to_staging(&plan, &mut fixture).is_err());
        assert!(fixture.writes().is_empty());
    }
}

#[test]
fn an_uncertain_private_promotion_is_read_back_without_a_second_patch() {
    for (label, failure, published) in [
        ("promotion-unverified", Failure::Before, false),
        ("promotion-confirmed", Failure::After, true),
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        state.promote_failure = failure;
        let mut fixture = HttpFixture::start(label, state);
        let result = publication_candidates::publish_to_staging(&plan, &mut fixture);
        if published {
            assert_eq!(result, Ok(Publication::Published));
        } else {
            assert_eq!(result, Err("Sentinel promotion HTTP failure"));
        }
        assert_eq!(fixture.writes().len(), 1);
        assert_eq!(
            fixture.state.lock().unwrap().release.as_ref().unwrap()["draft"],
            !published
        );
        if published {
            let state = fixture.state.lock().unwrap();
            let promoted = state
                .requests
                .iter()
                .position(|request| request["method"] == "PATCH")
                .unwrap();
            assert_eq!(state.requests[promoted]["response_status"], 502);
            exact_readback_after(&state, &plan, promoted, false);
        }
    }
}

#[test]
fn changed_or_extra_local_private_paths_are_rejected_before_any_api_request() {
    for scenario in ["changed-bytes", "private-ipa", "diagnostics", "hardlink"] {
        let (directory, plan) = candidate();
        let state = State::new(&plan, directory.path(), true);
        let name = plan.files().first_key_value().unwrap().0;
        let outside = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        match scenario {
            "changed-bytes" => {
                let mut bytes = fs::read(directory.path().join(name)).unwrap();
                bytes[0] ^= 1;
                fs::write(directory.path().join(name), bytes).unwrap();
            }
            "private-ipa" => fs::write(
                directory.path().join("ios-private.ipa"),
                b"synthetic private IPA",
            )
            .unwrap(),
            "diagnostics" => fs::write(
                directory.path().join("diagnostics.sealed"),
                b"synthetic sealed diagnostics",
            )
            .unwrap(),
            "hardlink" => {
                fs::rename(directory.path().join(name), outside.path().join(name)).unwrap();
                fs::hard_link(outside.path().join(name), directory.path().join(name)).unwrap();
            }
            _ => unreachable!(),
        }
        let mut fixture = HttpFixture::start(format!("local-inventory-{scenario}"), state);
        assert!(publication_candidates::publish_to_staging(&plan, &mut fixture).is_err());
        assert!(fixture.state.lock().unwrap().requests.is_empty());
    }
}

#[test]
fn an_owned_private_draft_is_checked_between_successful_uploads() {
    for (field, changed, error) in [
        (
            "body",
            json!("foreign owner after first successful upload"),
            "Staging release plan differs from reviewed identity",
        ),
        (
            "target_commitish",
            json!("c".repeat(40)),
            "Staging release source differs from reviewed identity",
        ),
        ("id", json!(8), "Staging release identity changed"),
        (
            "draft",
            json!(false),
            "Staging release no longer an owned draft",
        ),
    ] {
        let (directory, plan) = candidate_with_names(
            &environment(),
            &[
                "SHA256SUMS",
                "omniterm-1.2.3-linux-x64.tar.gz",
                "omniterm-1.2.3-linux-x64.tar.gz.sig",
            ],
        );
        let mut state = State::new(&plan, directory.path(), true);
        state.assets.pop_last();
        state.assets.pop_last();
        let (original_id, original) = state.assets.first_key_value().unwrap();
        let original_id = *original_id;
        let original_bytes = original.bytes.clone();
        state.upload_mutation = Some((field.into(), changed));
        let mut fixture = HttpFixture::start(format!("ownership-between-uploads-{field}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err(error)
        );
        assert_eq!(fixture.writes().len(), 1);
        assert_eq!(fixture.writes()[0]["method"], "POST");
        assert_eq!(fixture.writes()[0]["response_status"], 200);
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.assets[&original_id].bytes, original_bytes);
        assert_eq!(state.assets[&original_id].metadata["id"], original_id);
    }
}

#[test]
fn fresh_private_metadata_is_verified_after_a_successful_promotion_response() {
    let (directory, plan) = candidate();
    let mut state = State::new(&plan, directory.path(), true);
    state.promotion_readback_mutation = Some((
        "body".into(),
        json!("fresh metadata belongs to another plan"),
    ));
    let mut fixture = HttpFixture::start("fresh-promoted-metadata", state);
    assert_eq!(
        publication_candidates::publish_to_staging(&plan, &mut fixture),
        Err("Staging release plan differs from reviewed identity")
    );
    assert_eq!(fixture.writes().len(), 1);
    let state = fixture.state.lock().unwrap();
    let promoted = state
        .requests
        .iter()
        .position(|request| request["method"] == "PATCH")
        .unwrap();
    assert_eq!(
        state.requests[promoted]["response_json"]["body"],
        plan.notes()
    );
    assert!(
        state.requests[promoted + 1..]
            .iter()
            .any(|request| request["method"] == "GET"
                && request["endpoint"] == format!("repos/{STAGING_REPOSITORY}/releases/7"))
    );
}

#[test]
fn a_private_release_on_a_later_inventory_page_is_checked_before_any_write() {
    for scenario in ["same-identity", "conflict", "denied"] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), false);
        let first = (100..200)
            .map(|id| json!({"id":id,"tag_name":format!("ci-stage/ci-{id}-1")}))
            .collect::<Vec<_>>();
        state.release_pages.insert(1, json!(first));
        let second = match scenario {
            "same-identity" => json!([state.release.as_ref().unwrap()]),
            "conflict" => {
                state.release.as_mut().unwrap()["body"] = json!("another plan on page two");
                json!([state.release.as_ref().unwrap()])
            }
            "denied" => json!({"status":403}),
            _ => unreachable!(),
        };
        state.release_pages.insert(2, second);
        let mut fixture = HttpFixture::start(format!("release-page-two-{scenario}"), state);
        let result = publication_candidates::publish_to_staging(&plan, &mut fixture);
        if scenario == "same-identity" {
            assert_eq!(result, Ok(Publication::AlreadyPublished));
        } else {
            assert!(result.is_err());
        }
        assert!(fixture.writes().is_empty());
        assert!(
            fixture
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|request| request["endpoint"]
                    == format!("repos/{STAGING_REPOSITORY}/releases?per_page=100&page=2"))
        );
    }
}

#[test]
fn denied_private_asset_readback_or_changed_visibility_cannot_authorize_writes() {
    for scenario in ["download-denial", "asset-list-denial", "visibility-change"] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), scenario == "visibility-change");
        match scenario {
            "download-denial" => state.download_denial = true,
            "asset-list-denial" => state.asset_inventory = Some(json!({"status":403})),
            "visibility-change" => {
                state.assets.pop_last();
                state.repository_mutation =
                    Some((2, json!({"full_name":STAGING_REPOSITORY,"private":false})));
            }
            _ => unreachable!(),
        }
        let mut fixture = HttpFixture::start(format!("fresh-private-denial-{scenario}"), state);
        assert!(publication_candidates::publish_to_staging(&plan, &mut fixture).is_err());
        assert!(fixture.writes().is_empty());
        fixture.assert_preserved(&fixture.original);
    }
}

#[test]
fn the_canonical_plan_hash_is_part_of_private_draft_and_archive_identity() {
    let (directory, plan) = candidate();
    let (_other_directory, other) = candidate_with_names(
        &environment(),
        &[
            "SHA256SUMS",
            "omniterm-1.2.3-linux-x64.tar.gz",
            "omniterm-1.2.3-linux-x64.tar.gz.sig",
        ],
    );
    assert_eq!(plan.notes().lines().next(), other.notes().lines().next());
    assert_ne!(plan.notes(), other.notes());
    for draft in [false, true] {
        let mut state = State::new(&plan, directory.path(), draft);
        state.release.as_mut().unwrap()["body"] = json!(other.notes());
        let mut fixture = HttpFixture::start(format!("canonical-plan-conflict-{draft}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err("Staging release plan differs from reviewed identity")
        );
        assert!(fixture.writes().is_empty());
        fixture.assert_preserved(&fixture.original);
    }
}

#[test]
fn ownership_drift_during_the_last_asset_readback_prevents_promotion() {
    for (field, changed, error) in [
        (
            "body",
            json!("foreign owner during final byte readback"),
            "Staging release plan differs from reviewed identity",
        ),
        (
            "target_commitish",
            json!("c".repeat(40)),
            "Staging release source differs from reviewed identity",
        ),
        ("id", json!(8), "Staging release identity changed"),
        (
            "draft",
            json!(false),
            "Staging release no longer an owned draft",
        ),
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        state.assets.pop_last();
        let (original_id, original_asset) = state.assets.first_key_value().unwrap();
        let original_id = *original_id;
        let original_metadata = original_asset.metadata.clone();
        let original_bytes = original_asset.bytes.clone();
        state.metadata_after_uploaded_readback = Some((field.into(), changed));
        let mut fixture = HttpFixture::start(format!("drift-during-readback-{field}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err(error)
        );
        assert_eq!(fixture.writes().len(), 1);
        assert_eq!(fixture.writes()[0]["method"], "POST");
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.assets[&original_id].metadata, original_metadata);
        assert_eq!(state.assets[&original_id].bytes, original_bytes);
        let trigger = state
            .drift_request
            .expect("No complete post-upload byte readback");
        assert_eq!(state.requests[trigger]["method"], "GET");
        let uploaded = state
            .requests
            .iter()
            .position(|request| request["method"] == "POST")
            .unwrap();
        assert!(uploaded < trigger);
        assert_eq!(state.post_upload_readbacks.len(), plan.files().len());
    }
}

#[test]
fn a_correct_promotion_response_requires_fresh_exact_asset_readbacks() {
    for scenario in [
        "tamper",
        "replace",
        "missing",
        "extra",
        "starter",
        "duplicate-name",
        "duplicate-id",
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        state.promotion_asset_mutation = Some(scenario);
        let mut fixture = HttpFixture::start(format!("post-promotion-assets-{scenario}"), state);
        assert!(publication_candidates::publish_to_staging(&plan, &mut fixture).is_err());
        assert_eq!(fixture.writes().len(), 1);
        assert_eq!(fixture.writes()[0]["method"], "PATCH");
        assert_eq!(fixture.writes()[0]["response_status"], 200);
        assert_eq!(fixture.writes()[0]["response_json"]["body"], plan.notes());
        let state = fixture.state.lock().unwrap();
        let promoted = state
            .requests
            .iter()
            .position(|request| request["method"] == "PATCH")
            .unwrap();
        let fresh = &state.requests[promoted + 1..];
        assert!(fresh.iter().any(|request| request["method"] == "GET"
            && request["endpoint"] == format!("repos/{STAGING_REPOSITORY}/releases/7")));
        assert!(fresh.iter().any(|request| request["method"] == "GET"
            && request["endpoint"]
                == format!("repos/{STAGING_REPOSITORY}/releases/7/assets?per_page=100")));
    }
}

#[test]
fn an_uncertain_private_upload_requires_exact_stored_bytes_and_retained_ids() {
    for scenario in [
        "tamper",
        "starter",
        "duplicate-name",
        "duplicate-id",
        "missing",
        "replace",
        "extra",
        "release-id",
        "metadata-denial",
        "inventory-denial",
        "download-denial",
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        state.assets.pop_last();
        let (original_id, original) = state.assets.first_key_value().unwrap();
        let original_id = *original_id;
        let original_bytes = original.bytes.clone();
        state.upload_failure = Failure::After;
        match scenario {
            "release-id" => state.upload_mutation = Some(("id".into(), json!(8))),
            "replace" => state.upload_asset_mutation = Some("replace-first"),
            "metadata-denial" => {
                state.upload_read_denial = Some(format!("repos/{STAGING_REPOSITORY}/releases/7"))
            }
            "inventory-denial" => {
                state.upload_read_denial = Some(format!(
                    "repos/{STAGING_REPOSITORY}/releases/7/assets?per_page=100"
                ))
            }
            "download-denial" => {
                state.upload_read_denial =
                    Some(format!("repos/{STAGING_REPOSITORY}/releases/assets/12"))
            }
            other => state.upload_asset_mutation = Some(other),
        }
        let mut fixture = HttpFixture::start(format!("unsafe-upload-recovery-{scenario}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err("Sentinel upload HTTP failure")
        );
        assert_eq!(fixture.writes().len(), 1);
        assert_eq!(fixture.writes()[0]["method"], "POST");
        assert_eq!(fixture.writes()[0]["response_status"], 502);
        assert_eq!(
            fixture.state.lock().unwrap().assets[&if scenario == "replace" {
                99
            } else {
                original_id
            }]
                .bytes,
            original_bytes
        );
    }
}

#[test]
fn an_uncertain_private_create_requires_fresh_identity_and_exact_retained_assets() {
    for scenario in [
        "replacement-id",
        "conflicting-bytes",
        "unreviewed-assets",
        "metadata-denial",
        "inventory-denial",
        "enumeration-denial",
    ] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        state.release = None;
        state.create_failure = Failure::After;
        match scenario {
            "replacement-id" => state.metadata_mutation = Some(("id".into(), json!(8))),
            "conflicting-bytes" => state.mutate_assets("tamper"),
            "unreviewed-assets" => state.mutate_assets("extra"),
            "metadata-denial" => {
                state.create_read_denial = Some(format!("repos/{STAGING_REPOSITORY}/releases/7"))
            }
            "inventory-denial" => {
                state.create_read_denial = Some(format!(
                    "repos/{STAGING_REPOSITORY}/releases/7/assets?per_page=100"
                ))
            }
            "enumeration-denial" => {
                state.create_read_denial = Some(format!(
                    "repos/{STAGING_REPOSITORY}/releases?per_page=100&page=1"
                ))
            }
            _ => unreachable!(),
        }
        let original_assets = state.retained()["assets"].clone();
        let mut fixture = HttpFixture::start(format!("unsafe-create-recovery-{scenario}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err("Sentinel create HTTP failure")
        );
        assert_eq!(fixture.writes().len(), 1);
        assert_eq!(fixture.writes()[0]["response_status"], 502);
        assert_eq!(
            fixture.state.lock().unwrap().retained()["assets"],
            original_assets
        );
    }
}

#[test]
fn duplicate_release_identities_or_tags_across_pages_never_authorize_writes() {
    for scenario in ["id", "tag"] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), true);
        let mut first = (100..199)
            .map(|id| json!({"id":id,"tag_name":format!("ci-stage/ci-{id}-1")}))
            .collect::<Vec<_>>();
        first.push(state.release.clone().unwrap());
        state.release_pages.insert(1, json!(first));
        let second = if scenario == "id" {
            json!({"id":100,"tag_name":"ci-stage/duplicate-1"})
        } else {
            let mut duplicate = state.release.clone().unwrap();
            duplicate["id"] = json!(8);
            duplicate
        };
        state.release_pages.insert(2, json!([second]));
        let mut fixture =
            HttpFixture::start(format!("duplicate-release-across-pages-{scenario}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err(if scenario == "id" {
                "Duplicate release identity"
            } else {
                "Duplicate release tag"
            })
        );
        fixture.assert_preserved(&fixture.original);
    }
}

#[test]
fn denial_of_individual_private_release_readback_cannot_authorize_a_write() {
    for draft in [false, true] {
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), draft);
        state
            .denied_reads
            .insert(format!("repos/{STAGING_REPOSITORY}/releases/7"), 1);
        let mut fixture = HttpFixture::start(format!("individual-release-denial-{draft}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            Err("Sentinel readback HTTP failure")
        );
        fixture.assert_preserved(&fixture.original);
    }
}

#[test]
fn release_eng_membership_requires_an_active_matching_actor_over_loopback() {
    const CASE: &str = "OMNI_STAGING_MEMBERSHIP_CASE";
    const ACTOR: &str = "omni-synthetic-ci-actor";
    if let Ok(case) = std::env::var(CASE) {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(std::env::var("GITHUB_ACTOR").as_deref(), Ok(ACTOR));
        let (directory, plan) = candidate();
        let mut state = State::new(&plan, directory.path(), false);
        let expected = match case.as_str() {
            "active" => Ok(Publication::AlreadyPublished),
            "inactive" => {
                state.membership = json!({"state":"pending"});
                Err("Release actor is not an active member of Release Eng")
            }
            "denied" => {
                state.membership = json!({"status":403});
                Err("Sentinel readback HTTP failure")
            }
            "wrong-actor" => {
                state.membership_actor = Some("another-synthetic-ci-actor".into());
                Err("Sentinel readback HTTP failure")
            }
            _ => panic!("Unknown synthetic membership case: {case}"),
        };
        let mut fixture = HttpFixture::start(format!("membership-{case}"), state);
        assert_eq!(
            publication_candidates::publish_to_staging(&plan, &mut fixture),
            expected
        );
        fixture.assert_preserved(&fixture.original);
        let state = fixture.state.lock().unwrap();
        assert_eq!(
            state.requests[0]["endpoint"],
            format!("repos/{STAGING_REPOSITORY}")
        );
        let membership = &state.requests[1];
        assert_eq!(membership["method"], "GET");
        assert_eq!(
            membership["endpoint"],
            format!("orgs/omnisolo-llc/teams/release-eng/memberships/{ACTOR}")
        );
        if case == "active" {
            assert_eq!(membership["response_status"], 200);
            assert_eq!(membership["response_json"]["state"], "active");
            exact_readback_after(&state, &plan, 1, false);
        } else {
            assert_eq!(
                state.requests.len(),
                2,
                "Denied membership reached release state"
            );
            assert_eq!(
                membership["response_status"],
                if case == "inactive" {
                    200
                } else if case == "denied" {
                    403
                } else {
                    404
                }
            );
        }
        return;
    }
    // Each child supplies its own process actor context. This avoids global
    // environment mutation and exercises the real production membership gate.
    let safe = omni_release_launcher::clean_environment(&std::env::vars().collect());
    for case in ["active", "inactive", "denied", "wrong-actor"] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "release_eng_membership_requires_an_active_matching_actor_over_loopback",
                "--test-threads=1",
            ])
            .env_clear()
            .envs(&safe)
            .env("GITHUB_ACTIONS", "true")
            .env("GITHUB_ACTOR", ACTOR)
            .env(CASE, case);
        if let Ok(evidence) = std::env::var("OMNI_PRIVATE_STAGING_EVIDENCE") {
            child.env("OMNI_PRIVATE_STAGING_EVIDENCE", evidence);
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "Synthetic membership case {case} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
