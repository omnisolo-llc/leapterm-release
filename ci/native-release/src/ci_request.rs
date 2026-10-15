//! CI identity has no release/signing defaults. Observation checking is pure;
//! execution must acquire fresh observations in its trusted parent, never accept
//! a candidate-provided observation file as authorization.
use crate::{
    Environment, Result,
    input::{positive_number, valid_sha},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub const SOURCE_REPOSITORY: &str = "omnisolo-llc/leapterm";
pub const BUILDER_REPOSITORY: &str = "omnisolo-llc/leapterm-release";
pub const CI_WORKFLOW: &str =
    "omnisolo-llc/leapterm-release/.github/workflows/source-ci.yml@refs/heads/main";
pub const CI_STAGES: [&str; 13] = [
    "source",
    "security",
    "rust",
    "flutter-vm",
    "flutter-browser",
    "account",
    "vault",
    "worker",
    "web",
    "mcp",
    "relay",
    "packaging",
    "agent-lifecycle",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineIdentity {
    pub source_repository: String,
    pub source_sha: String,
    pub builder_repository: String,
    pub builder_sha: String,
    pub run_id: String,
    pub attempt: String,
}
impl PipelineIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.source_repository != SOURCE_REPOSITORY
            || self.builder_repository != BUILDER_REPOSITORY
            || !valid_sha(&self.source_sha)
            || !valid_sha(&self.builder_sha)
            || !positive_number(&self.run_id, 32)
            || !positive_number(&self.attempt, 16)
        {
            return Err("Invalid source-CI identity");
        }
        Ok(())
    }
    pub fn parse(value: &Value) -> Result<Self> {
        let result: Self = serde_json::from_value(value.clone())
            .map_err(|_| "Invalid source-CI identity fields")?;
        result.validate()?;
        Ok(result)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCiRequest {
    pub identity: PipelineIdentity,
    pub source_ref: String,
    pub stage: String,
    pub shard_index: u16,
    pub shard_count: u16,
}
pub fn valid_source_ref(value: &str) -> bool {
    value == "refs/heads/main"
        || value
            .strip_prefix("refs/pull/")
            .and_then(|s| s.strip_suffix("/head"))
            .is_some_and(|id| positive_number(id, 10))
}
impl SourceCiRequest {
    pub fn parse(value: &Value) -> Result<Self> {
        let result: Self = serde_json::from_value(value.clone())
            .map_err(|_| "Invalid source-CI request fields")?;
        result.identity.validate()?;
        if !valid_source_ref(&result.source_ref)
            || !CI_STAGES.contains(&result.stage.as_str())
            || result.shard_count == 0
            || result.shard_count > 64
            || result.shard_index >= result.shard_count
        {
            return Err("Invalid source-CI stage, ref or shard");
        }
        Ok(result)
    }
    pub fn parse_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() > 16_384 {
            return Err("Source-CI request exceeds bound");
        }
        Self::parse(&crate::json::parse(raw)?)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Repository {
    full_name: String,
    private: bool,
    default_branch: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    execution_repository: Repository,
    source_repository: Repository,
    github_actions: bool,
    event_name: String,
    execution_ref: String,
    workflow_ref: String,
    builder_sha: String,
    run_id: String,
    attempt: String,
    source_ref: String,
    source_head_repository: String,
    source_state: String,
    head_sha: String,
    base_sha: String,
    merge_base_sha: String,
    source_builder_sha: String,
    approved_source_sha: String,
    approved_builder_sha: String,
    approved_source_ref: String,
    approved_base_sha: String,
}
/// Validate fresh public-run and private-ref metadata supplied by the trusted
/// parent. A2 deliberately does not acquire source or issue an approval.
pub fn authorize_ci(request: &SourceCiRequest, observed: &Value) -> Result<()> {
    SourceCiRequest::parse(
        &serde_json::to_value(request).map_err(|_| "Invalid source-CI encoding")?,
    )?;
    let obs: Observation =
        serde_json::from_value(observed.clone()).map_err(|_| "Invalid source-CI observation")?;
    if !obs.github_actions
        || obs.event_name != "workflow_dispatch"
        || obs.execution_ref != "refs/heads/main"
        || obs.workflow_ref != CI_WORKFLOW
        || obs.execution_repository.full_name != BUILDER_REPOSITORY
        || obs.execution_repository.private
        || obs.execution_repository.default_branch != "main"
        || obs.source_repository.full_name != SOURCE_REPOSITORY
        || !obs.source_repository.private
        || obs.source_repository.default_branch != "main"
        || obs.source_head_repository != SOURCE_REPOSITORY
    {
        return Err("Source-CI origin or repository role is not authorized");
    }
    let id = &request.identity;
    if obs.builder_sha != id.builder_sha
        || obs.source_builder_sha != id.builder_sha
        || obs.run_id != id.run_id
        || obs.attempt != id.attempt
        || obs.head_sha != id.source_sha
        || obs.source_ref != request.source_ref
        || obs.approved_source_sha != id.source_sha
        || obs.approved_builder_sha != id.builder_sha
        || obs.approved_source_ref != request.source_ref
        || !valid_sha(&obs.base_sha)
        || obs.merge_base_sha != obs.base_sha
        || obs.approved_base_sha != obs.base_sha
    {
        return Err("Source-CI approval, source or run identity changed");
    }
    if request.source_ref == "refs/heads/main" {
        if obs.source_state != "main" || obs.base_sha != id.source_sha {
            return Err("Source-CI main identity changed");
        }
    } else if obs.source_state != "open" {
        return Err("Source-CI pull request is not open");
    }
    Ok(())
}
/// Reconstruct only the nonsecret stage protocol. In particular, no GITHUB_*
/// command-file/token prefix or arbitrary LEAP_* value is inherited.
pub fn ci_child_environment(
    parent: &Environment,
    request: &SourceCiRequest,
) -> Result<Environment> {
    let raw = serde_json::to_string(request).map_err(|_| "Invalid source-CI encoding")?;
    SourceCiRequest::parse_bytes(raw.as_bytes())?;
    let mut result = crate::clean_environment(parent);
    for (name, value) in [
        ("SOURCE_CI_REQUEST", raw),
        ("RELEASE_SOURCE_SHA", request.identity.source_sha.clone()),
        ("PUBLIC_BUILDER_SHA", request.identity.builder_sha.clone()),
        ("GITHUB_RUN_ID", request.identity.run_id.clone()),
        ("GITHUB_RUN_ATTEMPT", request.identity.attempt.clone()),
        ("GITHUB_REPOSITORY", BUILDER_REPOSITORY.into()),
        ("CI", "true".into()),
        ("CARGO_BUILD_JOBS", "2".into()),
        ("RUST_TEST_THREADS", "1".into()),
        ("FLUTTER_SUPPRESS_ANALYTICS", "true".into()),
        ("LEAP_REQUIRE_RELEASE_CONFIG", "true".into()),
    ] {
        result.insert(name.into(), value);
    }
    if let Some(catalog) = parent.get("SOURCE_CI_CATALOG_SHA256") {
        if !crate::source_api::hash(catalog) {
            return Err("Invalid source-CI catalog digest");
        }
        result.insert("SOURCE_CI_CATALOG_SHA256".into(), catalog.clone());
    }
    if request.stage == "agent-lifecycle"
        && let Some(predecessor) = parent.get("LEAP_E2E_AGENT_PREDECESSOR_COMMIT")
    {
        if !valid_sha(predecessor) || *predecessor == request.identity.source_sha {
            return Err("Invalid source-CI agent predecessor");
        }
        result.insert(
            "LEAP_E2E_AGENT_PREDECESSOR_COMMIT".into(),
            predecessor.clone(),
        );
    }
    Ok(result)
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = crate::guards::open_regular(path, max)?;
    let mut result = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut result)
        .map_err(|_| "CI metadata unreadable")?;
    if result.len() as u64 > max {
        return Err("CI metadata exceeds bound");
    }
    Ok(result)
}
/// Offline contract check only. Execution never treats this output as a receipt.
pub fn check_cli(args: &[String]) -> Result<()> {
    let mut values = std::collections::BTreeMap::<String, PathBuf>::new();
    let mut args = args.iter();
    while let Some(key) = args.next() {
        if !["--request", "--observation"].contains(&key.as_str()) || values.contains_key(key) {
            return Err("Invalid CI check arguments");
        }
        values.insert(
            key.clone(),
            PathBuf::from(args.next().ok_or("Missing CI check argument")?),
        );
    }
    if values.len() != 2 {
        return Err("CI request and observation are required");
    }
    let request = SourceCiRequest::parse_bytes(&read(&values["--request"], 16_384)?)?;
    let observed = crate::json::parse(&read(&values["--observation"], 65_536)?)?;
    authorize_ci(&request, &observed)?;
    println!("Source-CI identity is valid; no source acquired or workflow dispatched.");
    Ok(())
}
