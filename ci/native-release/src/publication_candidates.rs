//! The Actions exchange contains reviewed public candidates only. Preparation
//! acquires the native verifier from approved source before a write token exists.
//! Publication never selects source, evidence, private packages, or caller globs.
use crate::{
    Environment, Result,
    ci_request::PipelineIdentity,
    clean_environment, guards,
    input::{Request, validate_authority},
    process,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const REPOSITORY: &str = "omnisolo-llc/leapterm-release";
pub const DIRECTORY: &str = "reviewed-publication";
const MAX_ASSET: u64 = 2 * 1024 * 1024 * 1024 - 1;
const MAX_PLAN: u64 = 65536;

fn required<'a>(env: &'a Environment, key: &str) -> Result<&'a str> {
    env.get(key)
        .filter(|v| !v.is_empty())
        .map(String::as_str)
        .ok_or("Missing public candidate configuration")
}
pub fn request(env: &Environment) -> Result<Request> {
    validate_authority(env)?;
    if required(env, "RELEASE_TARGET")? != "publish" {
        return Err("Only the explicit publication target can publish");
    }
    let mut request = Request::parse(required(env, "RELEASE_REQUEST")?)?;
    request.resolve_from(env)?;
    if request.release_route != "option1"
        || request.build_only
        || request.preview_windows_self_sign
        || !matches!(request.verify_target.as_str(), "all" | "fast" | "slow")
        || request.source_sha.is_empty()
    {
        return Err("Verification-only requests cannot publish");
    }
    if !request.builder_sha.is_empty() && request.builder_sha != required(env, "GITHUB_SHA")? {
        return Err("Public candidate builder differs from this workflow");
    }
    Ok(request)
}
pub fn identity(env: &Environment) -> Result<PipelineIdentity> {
    validate_authority(env)?;
    let identity = PipelineIdentity {
        source_repository: required(env, "SOURCE_REPOSITORY")?.into(),
        source_sha: required(env, "RESOLVED_SOURCE_SHA")?.into(),
        builder_repository: required(env, "GITHUB_REPOSITORY")?.into(),
        builder_sha: required(env, "GITHUB_SHA")?.into(),
        run_id: required(env, "GITHUB_RUN_ID")?.into(),
        attempt: required(env, "GITHUB_RUN_ATTEMPT")?.into(),
    };
    identity.validate()?;
    Ok(identity)
}
/// Only the named verification configuration crosses into unpublished builders.
/// Cargo and tool tests continue to receive clean_environment, as before.
pub fn verification_environment(env: &Environment) -> Environment {
    let mut safe = clean_environment(env);
    for name in [
        "RELEASE_TARGET",
        "RELEASE_REQUEST",
        "RESOLVED_SOURCE_SHA",
        "RESOLVED_VERSION",
        "RESOLVED_BUILD_NUMBER",
        "BUILD_CONFIG",
        "SIGNING_CONFIG",
        "APPLE_CONFIG",
        "STORAGE_CONFIG",
        "DIAGNOSTICS_PUBLIC_KEY",
        "RUNNER_TEMP",
        "GITHUB_ACTIONS",
        "GITHUB_EVENT_NAME",
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "LEAPTERM_VPN_PROVIDER_PUBLIC_KEY",
        "LEAP_WINDOWS_SUITE_PUBLISHER_KEY_BASE64",
        "LEAP_WINDOWS_SUITE_APPROVAL_KEY_BASE64",
        "LEAPTERM_WINDOWS_SDK_MANIFEST_SHA256",
    ] {
        if let Some(value) = env.get(name) {
            safe.insert(name.into(), value.clone());
        }
    }
    if env.get("RELEASE_TARGET").map(String::as_str) == Some("windows")
        && env
            .get("RELEASE_REQUEST")
            .and_then(|raw| Request::parse(raw).ok())
            .is_some_and(|request| !request.build_only)
    {
        for name in [
            "LEAP_WINDOWS_ARTIFACT_SIGNING_DLIB",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        ] {
            if let Some(value) = env.get(name) {
                safe.insert(name.into(), value.clone());
            }
        }
    }
    safe
}
pub fn directory(env: &Environment) -> Result<PathBuf> {
    let runner = Path::new(required(env, "RUNNER_TEMP")?);
    safe_directory(runner)?;
    Ok(crate::retained_artifacts::ordinary(
        &runner
            .canonicalize()
            .map_err(|_| "Runner directory unavailable")?,
    )?
    .join(DIRECTORY))
}
fn safe_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err("Public candidate directory must be absolute");
    }
    for ancestor in path.ancestors() {
        guards::directory(ancestor)?;
    }
    Ok(())
}
pub fn digest(path: &Path, maximum: u64) -> Result<(u64, String)> {
    let mut file = guards::open_regular(path, maximum)?;
    let before = file
        .metadata()
        .map_err(|_| "Public candidate unavailable")?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "Public candidate unreadable")?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or("Public candidate exceeds bound")?;
        if bytes > maximum {
            return Err("Public candidate exceeds bound");
        }
        hash.update(&buffer[..count]);
    }
    guards::unchanged(&file, path)?;
    if bytes != before.len()
        || !guards::same(
            &before,
            &file.metadata().map_err(|_| "Public candidate changed")?,
        )
    {
        return Err("Public candidate changed while reading");
    }
    Ok((bytes, format!("{:x}", hash.finalize())))
}
fn read(path: &Path, maximum: u64) -> Result<Value> {
    let mut file = guards::open_regular(path, maximum)?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)
        .map_err(|_| "Public candidate manifest unreadable")?;
    guards::unchanged(&file, path)?;
    crate::json::parse(&raw)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Public candidate output must be fresh")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Public candidate write failed")
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    pub bytes: u64,
    pub sha256: String,
    pub content_type: String,
}
fn is_false(value: &bool) -> bool {
    !*value
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanDocument {
    schema: u8,
    identity: PipelineIdentity,
    release: Value,
    repository: String,
    files: BTreeMap<String, FileRecord>,
    #[serde(default, skip_serializing_if = "is_false")]
    windows_self_signed: bool,
}
pub struct Plan {
    document: PlanDocument,
    directory: PathBuf,
    hash: String,
}
impl Plan {
    pub fn source_repository(&self) -> &str {
        &self.document.identity.source_repository
    }
    pub fn files(&self) -> &BTreeMap<String, FileRecord> {
        &self.document.files
    }
    pub fn notes(&self) -> String {
        let disclosure = if self.document.windows_self_signed {
            "\n\nWindows executables and libraries use a self-signed Authenticode certificate. Windows may show trust warnings because this certificate is not trusted by a public certificate authority. Verify the detached OpenPGP package signatures using the reviewed release signing key. The Windows ZIP includes leapterm-windows-signing.cer as a public DER certificate; no private key material is included.\n"
        } else {
            ""
        };
        format!(
            "LeapTerm v{} ({}).{}\n<!-- native-publication:{} -->",
            self.document.release["version"].as_str().unwrap_or(""),
            self.document.identity.source_sha,
            disclosure,
            self.hash
        )
    }
    pub fn is_wave(&self) -> bool {
        self.document.release["verify_target"]
            .as_str()
            .is_some_and(|target| !target.is_empty() && target != "all")
    }
    pub fn tag(&self) -> String {
        let version = self.document.release["version"].as_str().unwrap_or("");
        match self.document.release["verify_target"].as_str() {
            Some(target) if !target.is_empty() && target != "all" => {
                format!("v{version}-{target}")
            }
            _ => format!("v{version}"),
        }
    }
    fn legacy_notes(&self) -> Result<Option<String>> {
        let name = format!(
            "leapterm-{}-release-provenance.json",
            self.document.release["version"]
                .as_str()
                .ok_or("Invalid release version")?
        );
        if !self.document.files.contains_key(&name) {
            return Ok(None);
        }
        let provenance = read(&self.directory.join(name), MAX_PLAN)?;
        for (field, value) in [
            ("source_sha", json!(self.document.identity.source_sha)),
            ("builder_sha", json!(self.document.identity.builder_sha)),
            ("run_id", json!(self.document.identity.run_id)),
            ("attempt", json!(self.document.identity.attempt)),
            ("version", self.document.release["version"].clone()),
            (
                "build_number",
                self.document.release["build_number"].clone(),
            ),
        ] {
            if provenance[field] != value {
                return Err("Legacy draft proof differs from the verified candidate");
            }
        }
        let proof = provenance["proof"]
            .as_str()
            .ok_or("Missing signed release proof")?;
        if proof.len() != 64
            || !proof
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Invalid signed release proof");
        }
        Ok(Some(format!("<!-- release-attempt:{proof} -->")))
    }
    fn verify_files(&self) -> Result<()> {
        safe_directory(&self.directory)?;
        let names: BTreeSet<_> = fs::read_dir(&self.directory)
            .map_err(|_| "Public candidate directory unreadable")?
            .map(|e| e.map(|e| e.file_name().into_string()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| "Public candidate directory unreadable")?
            .into_iter()
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| "Non-UTF8 public candidate name")?;
        if names != self.document.files.keys().cloned().collect() {
            return Err("Public candidate inventory differs from native plan");
        }
        for (name, record) in &self.document.files {
            verify_record(&self.directory.join(name), record)?;
        }
        Ok(())
    }
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && guards::safe_path(name)
}
fn verify_record(path: &Path, record: &FileRecord) -> Result<()> {
    if digest(path, MAX_ASSET)? != (record.bytes, record.sha256.clone()) {
        return Err("Public candidate bytes differ from native plan");
    }
    Ok(())
}
/// Structural/custody verification follows the approved native catalog verifier.
/// This does not treat producer manifests as classification or signature proof.
pub fn read_plan(value: &Value, env: &Environment, directory: &Path) -> Result<Plan> {
    let request = request(env)?;
    let document: PlanDocument =
        serde_json::from_value(value.clone()).map_err(|_| "Invalid public publication plan")?;
    if document.schema != 1
        || document.identity != identity(env)?
        || document.repository != REPOSITORY
        || document.release != crate::json::parse(request.normalized()?.as_bytes())?
        || document.files.is_empty()
        || document.files.len() >= 100
    {
        return Err("Public publication plan differs from this release");
    }
    let windows_self_signed = if let Some(raw) = env.get("BUILD_CONFIG") {
        let config = crate::json::parse(raw.as_bytes())?;
        match config
            .as_object()
            .ok_or("Invalid public build configuration")?
            .get("LEAP_WINDOWS_SELF_SIGNED")
        {
            None => false,
            Some(Value::String(value)) if value == "true" => true,
            Some(Value::String(value)) if value == "false" => false,
            Some(_) => return Err("Invalid LEAP_WINDOWS_SELF_SIGNED in build configuration"),
        }
    } else {
        false
    };
    if document.windows_self_signed != windows_self_signed {
        return Err("Windows signing disclosure differs from build configuration");
    }
    for (name, record) in &document.files {
        if !valid_name(name)
            || record.bytes == 0
            || record.bytes > MAX_ASSET
            || record.sha256.len() != 64
            || !record
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !["application/octet-stream", "application/json", "text/plain"]
                .contains(&record.content_type.as_str())
        {
            return Err("Invalid public candidate record");
        }
    }
    let canonical = serde_json::to_vec(&document).map_err(|_| "Invalid public publication plan")?;
    if canonical.len() > MAX_PLAN as usize {
        return Err("Public publication plan exceeds bound");
    }
    let plan = Plan {
        document,
        directory: directory.to_owned(),
        hash: format!("{:x}", Sha256::digest(canonical)),
    };
    plan.verify_files()?;
    Ok(plan)
}
/// Called only after the native child was built from acquired, byte-checked
/// approved source, and its read-only preparation completed successfully.
pub fn retain_verifier(env: &Environment, binary: &Path) -> Result<(String, String)> {
    request(env)?;
    let root = directory(env)?;
    safe_directory(&root)?;
    let plan = read(&root.join("plan.json"), MAX_PLAN)?;
    read_plan(&plan, env, &root.join("files"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::symlink_metadata(binary)
            && meta.nlink() > 1
        {
            let temp = binary.with_extension("single-link.tmp");
            fs::copy(binary, &temp).map_err(|_| "Failed to copy native binary")?;
            fs::rename(&temp, binary).map_err(|_| "Failed to replace native binary")?;
        }
    }
    let (bytes, sha256) = digest(binary, 256 * 1024 * 1024)?;
    let mut source = guards::open_regular(binary, 256 * 1024 * 1024)?;
    let destination = root.join(if cfg!(windows) {
        "native-verifier.exe"
    } else {
        "native-verifier"
    });
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o500).custom_flags(libc::O_NOFOLLOW);
    }
    let mut out = options
        .open(&destination)
        .map_err(|_| "Native verifier output must be fresh")?;
    std::io::copy(&mut source, &mut out)
        .and_then(|_| out.sync_all())
        .map_err(|_| "Native verifier copy failed")?;
    if digest(&destination, 256 * 1024 * 1024)? != (bytes, sha256.clone()) {
        return Err("Native verifier changed during copy");
    }
    write_new(
        &root.join("native-verifier.json"),
        &serde_json::to_vec(
            &json!({"schema":1,"identity":identity(env)?,"bytes":bytes,"sha256":sha256}),
        )
        .map_err(|_| "Native verifier identity unavailable")?,
    )?;
    let (_, plan_sha256) = digest(&root.join("plan.json"), MAX_PLAN)?;
    Ok((sha256, plan_sha256))
}
pub fn verify_prepared(env: &Environment) -> Result<Plan> {
    let request = request(env)?;
    let root = directory(env)?;
    safe_directory(&root)?;
    let custody = read(&root.join("native-verifier.json"), MAX_PLAN)?;
    let expected_verifier = required(env, "APPROVED_NATIVE_VERIFIER_SHA256")?;
    let expected_plan = required(env, "APPROVED_PUBLICATION_PLAN_SHA256")?;
    for hash in [expected_verifier, expected_plan] {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Invalid publication preparation output");
        }
    }
    let fields = custody
        .as_object()
        .ok_or("Invalid native verifier custody")?;
    if fields.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != ["schema", "identity", "bytes", "sha256"].into()
        || custody["schema"] != 1
        || PipelineIdentity::parse(&custody["identity"])? != identity(env)?
        || custody["sha256"] != expected_verifier
    {
        return Err("Native verifier does not belong to this release");
    }
    if digest(&root.join("plan.json"), MAX_PLAN)?.1 != expected_plan {
        return Err("Native publication plan differs from trusted preparation output");
    }
    let binary = root.join(if cfg!(windows) {
        "native-verifier.exe"
    } else {
        "native-verifier"
    });
    if digest(&binary, 256 * 1024 * 1024)?
        != (
            custody["bytes"]
                .as_u64()
                .ok_or("Invalid native verifier bytes")?,
            custody["sha256"]
                .as_str()
                .ok_or("Invalid native verifier hash")?
                .into(),
        )
    {
        return Err("Approved native verifier changed");
    }
    let mut safe = verification_environment(env);
    safe.remove("SIGNING_CONFIG");
    safe.remove("APPLE_CONFIG");
    safe.remove("STORAGE_CONFIG");
    safe.insert("RELEASE_REQUEST".into(), request.normalized()?);
    safe.insert(
        "PUBLIC_BUILDER_SHA".into(),
        required(env, "GITHUB_SHA")?.into(),
    );
    safe.insert(
        "RELEASE_INTEGRATION_SOURCE_REPOSITORY".into(),
        required(env, "SOURCE_REPOSITORY")?.into(),
    );
    safe.insert(
        "RELEASE_INTEGRATION_SOURCE_REF".into(),
        "refs/heads/main".into(),
    );
    safe.insert(
        "LEAP_RELEASE_SOURCE_ROOT".into(),
        root.to_string_lossy().into_owned(),
    );
    process::run(
        &binary,
        &[
            "helper".into(),
            "artifacts".into(),
            "verify-publication-plan".into(),
            "--directory".into(),
            root.join("files").to_string_lossy().into_owned(),
            "--plan".into(),
            root.join("plan.json").to_string_lossy().into_owned(),
        ],
        &root,
        &safe,
        Duration::from_secs(900),
        None,
    )?;
    if digest(&root.join("plan.json"), MAX_PLAN)?.1 != expected_plan {
        return Err("Native publication plan changed during verification");
    }
    read_plan(
        &read(&root.join("plan.json"), MAX_PLAN)?,
        env,
        &root.join("files"),
    )
}

pub trait ReleaseApi {
    fn get_json(&mut self, endpoint: &str) -> Result<Value>;
    fn write_json(&mut self, method: &str, endpoint: &str, body: &Value) -> Result<Value>;
    fn upload(&mut self, release: u64, name: &str, path: &Path) -> Result<Value>;
    fn download(&mut self, asset: u64, output: &Path) -> Result<()>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum Publication {
    Published,
    AlreadyPublished,
}
fn release(plan: &Plan, api: &mut impl ReleaseApi) -> Result<Option<Value>> {
    let mut found = None;
    let mut ids = BTreeSet::new();
    for page in 1..=100 {
        let value = api.get_json(&format!(
            "repos/{REPOSITORY}/releases?per_page=100&page={page}"
        ))?;
        let rows = value
            .as_array()
            .filter(|r| r.len() <= 100)
            .ok_or("Invalid release inventory")?;
        for row in rows {
            let id = row["id"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or("Invalid release identity")?;
            if !ids.insert(id) {
                return Err("Duplicate release identity");
            }
            let tag = row["tag_name"].as_str().ok_or("Invalid release tag")?;
            if tag == plan.tag() && found.replace(row.clone()).is_some() {
                return Err("Duplicate release tag");
            }
        }
        if rows.len() < 100 {
            return Ok(found);
        }
    }
    Err("Release inventory exceeds bound")
}
fn check_release(plan: &Plan, release: &Value) -> Result<(u64, bool)> {
    let id = release["id"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("Invalid release identity")?;
    let draft = release["draft"].as_bool().ok_or("Missing release state")?;
    if release["tag_name"] != plan.tag()
        || release["target_commitish"] != plan.document.identity.builder_sha
        || (release["body"] != plan.notes()
            && !(draft
                && plan
                    .legacy_notes()?
                    .is_some_and(|notes| release["body"] == notes)))
        || release["prerelease"] != false
    {
        return Err("Existing release belongs to different reviewed bytes");
    }
    Ok((id, draft))
}
fn assets(
    plan: &Plan,
    api: &mut impl ReleaseApi,
    id: u64,
    complete: bool,
) -> Result<BTreeMap<String, u64>> {
    let value = api.get_json(&format!(
        "repos/{REPOSITORY}/releases/{id}/assets?per_page=100"
    ))?;
    let rows = value
        .as_array()
        .filter(|rows| rows.len() < 100)
        .ok_or("Incomplete asset inventory")?;
    let mut result = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let directory = tempfile::tempdir().map_err(|_| "Asset readback directory unavailable")?;
    for asset in rows {
        let name = asset["name"].as_str().ok_or("Invalid release asset name")?;
        let record = plan
            .document
            .files
            .get(name)
            .ok_or("Release contains an unreviewed asset")?;
        let asset_id = asset["id"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("Invalid asset identity")?;
        if asset["state"] != "uploaded"
            || asset["size"] != record.bytes
            || !ids.insert(asset_id)
            || result.insert(name.into(), asset_id).is_some()
        {
            return Err("Invalid or duplicate release asset");
        }
        let path = directory.path().join(name);
        api.download(asset_id, &path)?;
        verify_record(&path, record)?;
    }
    if complete
        && result.keys().collect::<Vec<_>>() != plan.document.files.keys().collect::<Vec<_>>()
    {
        return Err("Existing public release is incomplete");
    }
    Ok(result)
}
pub fn publish(plan: &Plan, api: &mut impl ReleaseApi) -> Result<Publication> {
    plan.verify_files()?;
    let repository = api.get_json(&format!("repos/{REPOSITORY}"))?;
    if repository["full_name"] != REPOSITORY || repository["private"] != false {
        return Err("Public repository visibility differs from reviewed scope");
    }
    let existing = release(plan, api)?;
    let info = match existing {
        Some(info) => info,
        None => api.write_json("POST",&format!("repos/{REPOSITORY}/releases"),&json!({"tag_name":plan.tag(),"target_commitish":plan.document.identity.builder_sha,"name":format!("LeapTerm {}",plan.tag()),"body":plan.notes(),"draft":true,"prerelease":false}))?,
    };
    let (id, draft) = check_release(plan, &info)?;
    let existing = assets(plan, api, id, !draft)?;
    if !draft {
        return Ok(Publication::AlreadyPublished);
    }
    if info["body"] != plan.notes() {
        // The signed current proof and EVERY existing asset have already been
        // verified. Bind the same draft to the exact plan before adding bytes.
        let bound = api.write_json(
            "PATCH",
            &format!("repos/{REPOSITORY}/releases/{id}"),
            &json!({"body":plan.notes()}),
        )?;
        if check_release(plan, &bound)? != (id, true) || bound["body"] != plan.notes() {
            return Err("Legacy draft did not retain its verified identity");
        }
    }
    for (name, record) in &plan.document.files {
        if existing.contains_key(name) {
            continue;
        }
        let path = plan.directory.join(name);
        verify_record(&path, record)?;
        let uploaded = api.upload(id, name, &path)?;
        if uploaded["name"] != *name
            || uploaded["state"] != "uploaded"
            || uploaded["size"] != record.bytes
            || uploaded["id"].as_u64().is_none_or(|n| n == 0)
        {
            return Err("Public asset upload response differs from candidate");
        }
    }
    plan.verify_files()?;
    assets(plan, api, id, true)?;
    let updated = api.write_json(
        "PATCH",
        &format!("repos/{REPOSITORY}/releases/{id}"),
        &json!({"draft":false,"make_latest":"true"}),
    )?;
    if check_release(plan, &updated)? != (id, false) {
        return Err("Public release promotion did not preserve identity");
    }
    let current = api.get_json(&format!("repos/{REPOSITORY}/releases/{id}"))?;
    if check_release(plan, &current)? != (id, false) {
        return Err("Published release readback differs from native plan");
    }
    assets(plan, api, id, true)?;
    Ok(Publication::Published)
}

fn release_for_repo(plan: &Plan, api: &mut impl ReleaseApi, repo: &str) -> Result<Option<Value>> {
    let mut found = None;
    let mut ids = BTreeSet::new();
    for page in 1..=100 {
        let value = api.get_json(&format!("repos/{repo}/releases?per_page=100&page={page}"))?;
        let rows = value
            .as_array()
            .filter(|r| r.len() <= 100)
            .ok_or("Invalid release inventory")?;
        for row in rows {
            let id = row["id"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or("Invalid release identity")?;
            if !ids.insert(id) {
                return Err("Duplicate release identity");
            }
            let tag = row["tag_name"].as_str().ok_or("Invalid release tag")?;
            if tag == plan.tag() && found.replace(row.clone()).is_some() {
                return Err("Duplicate release tag");
            }
        }
        if rows.len() < 100 {
            return Ok(found);
        }
    }
    Err("Release inventory exceeds bound")
}

fn assets_for_repo(
    plan: &Plan,
    api: &mut impl ReleaseApi,
    repo: &str,
    id: u64,
    complete: bool,
) -> Result<BTreeMap<String, u64>> {
    let value = api.get_json(&format!("repos/{repo}/releases/{id}/assets?per_page=100"))?;
    let rows = value
        .as_array()
        .filter(|rows| rows.len() < 100)
        .ok_or("Incomplete asset inventory")?;
    let mut result = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let directory = tempfile::tempdir().map_err(|_| "Asset readback directory unavailable")?;
    for asset in rows {
        let name = asset["name"].as_str().ok_or("Invalid release asset name")?;
        let record = plan
            .document
            .files
            .get(name)
            .ok_or("Release contains an unreviewed asset")?;
        let asset_id = asset["id"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("Invalid asset identity")?;
        if asset["state"] != "uploaded"
            || asset["size"] != record.bytes
            || !ids.insert(asset_id)
            || result.insert(name.into(), asset_id).is_some()
        {
            return Err("Invalid or duplicate release asset");
        }
        let path = directory.path().join(name);
        api.download(asset_id, &path)?;
        verify_record(&path, record)?;
    }
    if complete
        && result.keys().collect::<Vec<_>>() != plan.document.files.keys().collect::<Vec<_>>()
    {
        return Err("Existing staging release is incomplete");
    }
    Ok(result)
}

fn check_staging_repository(plan: &Plan, api: &mut impl ReleaseApi) -> Result<()> {
    let repo = plan.source_repository();
    let repository = api.get_json(&format!("repos/{repo}"))?;
    if repository["full_name"] != repo || repository["private"] != true {
        return Err("Private staging repository visibility differs from reviewed scope");
    }
    Ok(())
}

fn check_staging_release(plan: &Plan, info: &Value) -> Result<(u64, bool)> {
    let id = info["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or("Invalid release identity")?;
    let draft = info["draft"].as_bool().ok_or("Missing release state")?;
    if info["tag_name"] != plan.tag() {
        return Err("Staging release tag differs from reviewed identity");
    }
    if info["target_commitish"] != plan.document.identity.source_sha {
        return Err("Staging release source differs from reviewed identity");
    }
    if info["body"] != plan.notes() {
        return Err("Staging release plan differs from reviewed identity");
    }
    if info["prerelease"] != false {
        return Err("Staging release prerelease state differs from reviewed identity");
    }
    Ok((id, draft))
}

fn check_staging_state(plan: &Plan, info: &Value, id: u64, draft: bool) -> Result<()> {
    let (current_id, current_draft) = check_staging_release(plan, info)?;
    if current_id != id {
        return Err("Staging release identity changed");
    }
    if current_draft != draft {
        return Err(if draft {
            "Staging release no longer an owned draft"
        } else {
            "Staging published release state changed"
        });
    }
    Ok(())
}

fn staging_owner(plan: &Plan, api: &mut impl ReleaseApi, id: u64, draft: bool) -> Result<()> {
    let repo = plan.source_repository();
    let current = api.get_json(&format!("repos/{repo}/releases/{id}"))?;
    check_staging_state(plan, &current, id, draft)?;
    let listed = release_for_repo(plan, api, repo)?.ok_or("Staging release no longer available")?;
    check_staging_state(plan, &listed, id, draft)
}

fn staging_inventory(
    plan: &Plan,
    api: &mut impl ReleaseApi,
    id: u64,
) -> Result<BTreeMap<String, u64>> {
    let repo = plan.source_repository();
    let value = api.get_json(&format!("repos/{repo}/releases/{id}/assets?per_page=100"))?;
    let rows = value
        .as_array()
        .filter(|rows| rows.len() < 100)
        .ok_or("Incomplete asset inventory")?;
    let mut inventory = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for asset in rows {
        let name = asset["name"].as_str().ok_or("Invalid release asset name")?;
        let record = plan
            .document
            .files
            .get(name)
            .ok_or("Release contains an unreviewed asset")?;
        let id = asset["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .ok_or("Invalid asset identity")?;
        if asset["state"] != "uploaded"
            || asset["size"] != record.bytes
            || !ids.insert(id)
            || inventory.insert(name.into(), id).is_some()
        {
            return Err("Invalid or duplicate release asset");
        }
    }
    Ok(inventory)
}

fn staging_readback(
    plan: &Plan,
    api: &mut impl ReleaseApi,
    id: u64,
    draft: bool,
    retained: &BTreeMap<String, u64>,
    complete: bool,
) -> Result<BTreeMap<String, u64>> {
    let repo = plan.source_repository();
    check_staging_repository(plan, api)?;
    staging_owner(plan, api, id, draft)?;
    let inventory = assets_for_repo(plan, api, repo, id, complete)?;
    if staging_inventory(plan, api, id)? != inventory
        || retained
            .iter()
            .any(|(name, id)| inventory.get(name) != Some(id))
    {
        return Err("Staging release asset identities changed");
    }
    // Ownership and private repository authority are refreshed after byte
    // downloads, so a change during readback cannot authorize the next write.
    check_staging_repository(plan, api)?;
    staging_owner(plan, api, id, draft)?;
    Ok(inventory)
}

pub fn publish_to_staging(plan: &Plan, api: &mut impl ReleaseApi) -> Result<Publication> {
    let repo = plan.source_repository();
    plan.verify_files()?;
    check_staging_repository(plan, api)?;
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && let Ok(actor) = std::env::var("GITHUB_ACTOR")
    {
        let actor = actor.trim();
        if !actor.is_empty() {
            let membership = api.get_json(&format!(
                "orgs/omnisolo-llc/teams/release-eng/memberships/{actor}"
            ))?;
            if membership["state"] != "active" {
                return Err("Release actor is not an active member of Release Eng");
            }
        }
    }
    let existing = release_for_repo(plan, api, repo)?;
    let (id, draft, mut retained) = match existing {
        Some(info) => {
            // Conflicting same-version releases are immutable, including
            // published archives and drafts owned by another Plan identity.
            let (id, draft) = check_staging_release(plan, &info)?;
            let retained = staging_readback(plan, api, id, draft, &BTreeMap::new(), !draft)?;
            (id, draft, retained)
        }
        None => {
            check_staging_repository(plan, api)?;
            if release_for_repo(plan, api, repo)?.is_some() {
                return Err("Staging release appeared before creation");
            }
            let created = api.write_json(
                "POST",
                &format!("repos/{repo}/releases"),
                &json!({
                    "tag_name": plan.tag(),
                    "target_commitish": plan.document.identity.source_sha,
                    "name": format!("LeapTerm {}", plan.tag()),
                    "body": plan.notes(),
                    "draft": true,
                    "prerelease": false
                }),
            );
            match created {
                Ok(info) => {
                    let (id, draft) = check_staging_release(plan, &info)?;
                    check_staging_state(plan, &info, id, true)?;
                    let retained = staging_readback(plan, api, id, true, &BTreeMap::new(), false)?;
                    (id, draft, retained)
                }
                Err(error) => {
                    let mut recover = || -> Result<(u64, bool, BTreeMap<String, u64>)> {
                        check_staging_repository(plan, api)?;
                        let info = release_for_repo(plan, api, repo)?
                            .ok_or("Staging creation could not be verified")?;
                        let (id, draft) = check_staging_release(plan, &info)?;
                        check_staging_state(plan, &info, id, true)?;
                        let retained =
                            staging_readback(plan, api, id, true, &BTreeMap::new(), false)?;
                        Ok((id, draft, retained))
                    };
                    recover().map_err(|_| error)?
                }
            }
        }
    };
    if !draft {
        return Ok(Publication::AlreadyPublished);
    }
    for (name, record) in &plan.document.files {
        if retained.contains_key(name) {
            continue;
        }
        let path = plan.directory.join(name);
        verify_record(&path, record)?;
        let current = staging_readback(plan, api, id, true, &retained, false)?;
        if current != retained {
            return Err("Staging release asset identities changed");
        }
        match api.upload(id, name, &path) {
            Ok(uploaded) => {
                let asset_id = uploaded["id"]
                    .as_u64()
                    .filter(|id| *id > 0)
                    .ok_or("Staging asset upload response differs from candidate")?;
                if uploaded["name"] != *name
                    || uploaded["state"] != "uploaded"
                    || uploaded["size"] != record.bytes
                    || retained.values().any(|id| *id == asset_id)
                {
                    return Err("Staging asset upload response differs from candidate");
                }
                retained.insert(name.clone(), asset_id);
            }
            Err(error) => {
                let recovered =
                    staging_readback(plan, api, id, true, &retained, false).map_err(|_| error)?;
                if recovered.len() != retained.len() + 1 || !recovered.contains_key(name) {
                    return Err(error);
                }
                retained = recovered;
            }
        }
    }
    plan.verify_files()?;
    if staging_readback(plan, api, id, true, &retained, true)? != retained {
        return Err("Staging release asset identities changed");
    }
    let promoted = api.write_json(
        "PATCH",
        &format!("repos/{repo}/releases/{id}"),
        &json!({
            "draft": false,
            "make_latest": if plan.is_wave() { "false" } else { "true" }
        }),
    );
    match promoted {
        Ok(updated) => {
            check_staging_state(plan, &updated, id, false)?;
            if staging_readback(plan, api, id, false, &retained, true)? != retained {
                return Err("Staging release asset identities changed");
            }
        }
        Err(error) => {
            let recovered =
                staging_readback(plan, api, id, false, &retained, true).map_err(|_| error)?;
            if recovered != retained {
                return Err(error);
            }
        }
    }
    Ok(Publication::Published)
}

pub struct GitHub {
    env: Environment,
    work: PathBuf,
    repo: String,
}
impl GitHub {
    pub fn new(env: &Environment, work: &Path) -> Result<Self> {
        Self::new_for_repo(env, work, REPOSITORY)
    }
    pub fn new_for_repo(env: &Environment, work: &Path, repo: &str) -> Result<Self> {
        let mut safe = clean_environment(env);
        safe.insert("GH_TOKEN".into(), required(env, "GH_TOKEN")?.into());
        safe.insert("GH_PROMPT_DISABLED".into(), "1".into());
        Ok(Self {
            env: safe,
            work: work.into(),
            repo: repo.into(),
        })
    }
    fn api(&self, arguments: Vec<String>) -> Result<Vec<u8>> {
        process::run(
            Path::new("gh"),
            &arguments,
            &self.work,
            &self.env,
            Duration::from_secs(900),
            None,
        )
    }
}
impl ReleaseApi for GitHub {
    fn get_json(&mut self, endpoint: &str) -> Result<Value> {
        crate::json::parse(&self.api(vec![
            "api".into(),
            "--hostname".into(),
            "github.com".into(),
            endpoint.into(),
        ])?)
    }
    fn write_json(&mut self, method: &str, endpoint: &str, body: &Value) -> Result<Value> {
        let file =
            tempfile::NamedTempFile::new_in(&self.work).map_err(|_| "API input unavailable")?;
        fs::write(
            file.path(),
            serde_json::to_vec(body).map_err(|_| "API input encoding failed")?,
        )
        .map_err(|_| "API input write failed")?;
        crate::json::parse(&self.api(vec![
            "api".into(),
            "--hostname".into(),
            "github.com".into(),
            "--method".into(),
            method.into(),
            endpoint.into(),
            "--input".into(),
            file.path().to_string_lossy().into_owned(),
        ])?)
    }
    fn upload(&mut self, release: u64, name: &str, path: &Path) -> Result<Value> {
        if !valid_name(name) {
            return Err("Invalid public upload name");
        }
        crate::json::parse(&self.api(vec![
            "api".into(),
            "--hostname".into(),
            "github.com".into(),
            "--method".into(),
            "POST".into(),
            format!(
                "https://uploads.github.com/repos/{}/releases/{release}/assets?name={name}",
                self.repo
            ),
            "--header".into(),
            "Content-Type: application/octet-stream".into(),
            "--input".into(),
            path.to_string_lossy().into_owned(),
        ])?)
    }
    fn download(&mut self, asset: u64, output: &Path) -> Result<()> {
        // Asset bytes can exceed the supervisor's bounded stdout. A private
        // file receives the download and is verified before any promotion.
        let url = format!(
            "https://api.github.com/repos/{}/releases/assets/{asset}",
            self.repo
        );
        let mut safe = clean_environment(&self.env);
        // A config file keeps the token off the argv and out of public logs.
        let config = tempfile::NamedTempFile::new_in(&self.work)
            .map_err(|_| "Asset readback config unavailable")?;
        let token = required(&self.env, "GH_TOKEN")?;
        if token.contains(['\r', '\n', '\0', '"', '\\']) {
            return Err("Invalid public readback token");
        }
        fs::write(config.path(),format!("header = \"Authorization: Bearer {token}\"\nheader = \"Accept: application/octet-stream\"\n")).map_err(|_| "Asset readback config unavailable")?;
        safe.remove("GH_TOKEN");
        process::run(
            Path::new("curl"),
            &[
                "--disable".into(),
                "--config".into(),
                config.path().to_string_lossy().into_owned(),
                "--silent".into(),
                "--show-error".into(),
                "--fail".into(),
                "--location".into(),
                "--proto".into(),
                "=https".into(),
                "--proto-redir".into(),
                "=https".into(),
                "--max-time".into(),
                "900".into(),
                "--max-filesize".into(),
                MAX_ASSET.to_string(),
                "--output".into(),
                output.to_string_lossy().into_owned(),
                url,
            ],
            &self.work,
            &safe,
            Duration::from_secs(930),
            None,
        )?;
        guards::open_regular(output, MAX_ASSET)?;
        Ok(())
    }
}
