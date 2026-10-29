//! Metadata selection is separate from checkout authority. Authority is acquired
//! fresh from canonical GitHub repositories and a protected exact-run approval;
//! no caller-provided file or discovery result is an approval.
use crate::{
    Environment, Result,
    ci_request::{self, BUILDER_REPOSITORY, CI_STAGES, PipelineIdentity, SourceCiRequest},
    source_api::{self, GitHubApi, Role, SourceApi, fields, hash, json_digest, number, text},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const AUTHORITY_ENVIRONMENT: &str = "source-ci-authority";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageApproval {
    pub stage: String,
    pub shard_index: u16,
    pub shard_count: u16,
    pub request_sha256: String,
    pub case_ids_sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub schema: String,
    pub identity: PipelineIdentity,
    pub source_ref: String,
    pub base_sha: String,
    pub catalog_sha256: String,
    pub workflow_inventory_sha256: String,
    pub not_before_epoch: u64,
    pub expires_epoch: u64,
    pub requests: Vec<StageApproval>,
}
impl Approval {
    pub fn parse_at(value: &Value, now: u64) -> Result<Self> {
        let result: Self = serde_json::from_value(value.clone())
            .map_err(|_| "Invalid Source-CI approval fields")?;
        result.identity.validate()?;
        if result.schema != "leapterm.source-ci.approval.v1"
            || !ci_request::valid_source_ref(&result.source_ref)
            || !crate::input::valid_sha(&result.base_sha)
            || !hash(&result.catalog_sha256)
            || !hash(&result.workflow_inventory_sha256)
            || result.not_before_epoch > now
            || now >= result.expires_epoch
            || result.expires_epoch.saturating_sub(result.not_before_epoch) > 86400
            || result.requests.len() != CI_STAGES.len()
        {
            return Err("Source-CI approval is incomplete or expired");
        }
        let mut seen = BTreeSet::new();
        for stage in &result.requests {
            if !CI_STAGES.contains(&stage.stage.as_str())
                || !seen.insert(&stage.stage)
                || stage.shard_index != 0
                || stage.shard_count != 1
                || !hash(&stage.request_sha256)
                || !hash(&stage.case_ids_sha256)
            {
                return Err("Invalid Source-CI approved matrix");
            }
            let request = SourceCiRequest {
                identity: result.identity.clone(),
                source_ref: result.source_ref.clone(),
                stage: stage.stage.clone(),
                shard_index: stage.shard_index,
                shard_count: stage.shard_count,
            };
            if request_digest(&request)? != stage.request_sha256 {
                return Err("Source-CI approval request changed");
            }
        }
        if result.source_ref == "refs/heads/main" && result.base_sha != result.identity.source_sha {
            return Err("Source-CI approved base changed");
        }
        Ok(result)
    }
    pub fn stage(&self, request: &SourceCiRequest) -> Result<&StageApproval> {
        if request.identity != self.identity || request.source_ref != self.source_ref {
            return Err("Source-CI approval identity changed");
        }
        self.requests
            .iter()
            .find(|s| {
                s.stage == request.stage
                    && s.shard_index == request.shard_index
                    && s.shard_count == request.shard_count
                    && request_digest(request).as_ref() == Ok(&s.request_sha256)
            })
            .ok_or("Source-CI shard is not approved")
    }
    pub fn digest(&self) -> Result<String> {
        json_digest(&serde_json::to_value(self).map_err(|_| "Invalid Source-CI approval encoding")?)
    }
}
pub fn request_digest(request: &SourceCiRequest) -> Result<String> {
    json_digest(&serde_json::to_value(request).map_err(|_| "Invalid Source-CI request encoding")?)
}
pub fn correlation_id(
    source_repository: &str,
    source_sha: &str,
    release_builder_sha: &str,
    stage: &str,
) -> String {
    let payload =
        format!("leap-source-ci-v1:{source_repository}:{source_sha}:{release_builder_sha}:{stage}");
    source_api::digest(payload.as_bytes())[..24].to_owned()
}
pub fn valid_correlation_id(value: &str) -> bool {
    value.len() == 24
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn repository(value: &Value, name: &str, private: bool) -> Result<Value> {
    if value["full_name"] != name
        || value["private"] != private
        || value["default_branch"] != "main"
    {
        return Err("Source-CI repository role changed");
    }
    Ok(json!({"full_name":name,"private":private,"default_branch":"main"}))
}
pub fn require_origin(env: &Environment, workflow: &str, events: &[&str]) -> Result<()> {
    let expected = format!("{BUILDER_REPOSITORY}/.github/workflows/{workflow}@refs/heads/main");
    if env.get("GITHUB_ACTIONS").map(String::as_str) != Some("true")
        || env.get("GITHUB_REPOSITORY").map(String::as_str) != Some(BUILDER_REPOSITORY)
        || env.get("GITHUB_REF").map(String::as_str) != Some("refs/heads/main")
        || env.get("GITHUB_WORKFLOW_REF") != Some(&expected)
        || !env
            .get("GITHUB_EVENT_NAME")
            .is_some_and(|v| events.contains(&v.as_str()))
        || env.get("RUNNER_ENVIRONMENT").map(String::as_str) != Some("github-hosted")
    {
        return Err("Source-CI trusted workflow origin denied");
    }
    Ok(())
}
pub fn acquire_approval(
    public: &mut dyn SourceApi,
    protected: &mut dyn SourceApi,
    run_id: &str,
    attempt: &str,
    now: u64,
) -> Result<Approval> {
    if !crate::input::positive_number(run_id, 32) || !crate::input::positive_number(attempt, 16) {
        return Err("Invalid Source-CI approval run");
    }
    let root = format!("repos/{BUILDER_REPOSITORY}");
    let variable=protected.get_json(&format!("{root}/environments/{AUTHORITY_ENVIRONMENT}/variables/SOURCE_CI_APPROVAL_{run_id}_{attempt}"))?;
    if variable["name"] != format!("SOURCE_CI_APPROVAL_{run_id}_{attempt}") {
        return Err("Source-CI approval variable changed");
    }
    let raw = text(&variable, "value")?;
    if raw.len() > 65536 {
        return Err("Source-CI approval exceeds bound");
    }
    let approval = Approval::parse_at(&crate::json::parse(raw.as_bytes())?, now)?;
    if approval.identity.run_id != run_id || approval.identity.attempt != attempt {
        return Err("Source-CI approved run changed");
    }
    let environment =
        protected.get_json(&format!("{root}/environments/{AUTHORITY_ENVIRONMENT}"))?;
    let environment_id = number(&environment, "id")?;
    if environment["name"] != AUTHORITY_ENVIRONMENT
        || environment["deployment_branch_policy"]
            != json!({"protected_branches":true,"custom_branch_policies":false})
        || environment["can_admins_bypass"] != false
    {
        return Err("Source-CI protected environment policy unavailable");
    }
    let rules = environment["protection_rules"]
        .as_array()
        .ok_or("Source-CI reviewers unavailable")?;
    let reviewer_rules = rules
        .iter()
        .filter(|r| r["type"] == "required_reviewers")
        .collect::<Vec<_>>();
    if reviewer_rules.len() != 1 || reviewer_rules[0]["prevent_self_review"] != true {
        return Err("Source-CI reviewer policy unavailable");
    }
    let reviewers = reviewer_rules[0]["reviewers"]
        .as_array()
        .ok_or("Source-CI reviewers unavailable")?;
    if reviewers.is_empty() || reviewers.len() > 6 {
        return Err("Source-CI reviewer policy unavailable");
    }
    let mut reviewer_ids = BTreeSet::new();
    for reviewer in reviewers {
        if reviewer["type"] != "User" || !reviewer_ids.insert(number(&reviewer["reviewer"], "id")?)
        {
            return Err("Source-CI reviewer policy is unresolved");
        }
    }
    let run = public.get_json(&format!("{root}/actions/runs/{run_id}"))?;
    let actor = number(&run["actor"], "id")?;
    if run["run_attempt"]
        .as_u64()
        .map(|v| v.to_string())
        .as_deref()
        != Some(attempt)
    {
        return Err("Source-CI approval attempt changed");
    }
    let reviews = public.get_json(&format!("{root}/actions/runs/{run_id}/approvals"))?;
    let reviews = reviews
        .as_array()
        .ok_or("Source-CI approval reviews unavailable")?;
    if reviews.is_empty() || reviews.len() > 100 {
        return Err("Source-CI approval reviews unavailable");
    }
    let comment = format!("leapterm-source-ci-approval:{}", approval.digest()?);
    let mut approved = false;
    for review in reviews {
        let environments = review["environments"]
            .as_array()
            .ok_or("Source-CI reviewed environment unavailable")?;
        if !environments
            .iter()
            .any(|e| e["id"].as_u64() == Some(environment_id) && e["name"] == AUTHORITY_ENVIRONMENT)
        {
            continue;
        }
        // Any later rejection for this exact binding prevents reusing an older approval.
        if review["comment"] == comment {
            if review["state"] != "approved" {
                return Err("Source-CI approval was rejected");
            }
            let reviewer = number(&review["user"], "id")?;
            if reviewer == actor || !reviewer_ids.contains(&reviewer) {
                return Err("Source-CI review identity denied");
            }
            approved = true;
        }
    }
    if !approved {
        return Err("Source-CI exact approval is missing");
    }
    Ok(approval)
}
pub fn fresh_source(
    source: &mut dyn SourceApi,
    request: &SourceCiRequest,
    approval: &Approval,
) -> Result<Value> {
    approval.stage(request)?;
    fresh_binding(
        source,
        &request.identity.source_repository,
        &request.source_ref,
        &request.identity.source_sha,
        &request.identity.builder_sha,
        &approval.base_sha,
        &approval.workflow_inventory_sha256,
    )
}
fn fresh_binding(
    source: &mut dyn SourceApi,
    source_repo: &str,
    source_ref: &str,
    source_sha: &str,
    builder_sha: &str,
    base_sha: &str,
    inventory_sha256: &str,
) -> Result<Value> {
    if !crate::input::valid_repo_slug(source_repo)
        || !ci_request::valid_source_ref(source_ref)
        || !crate::input::valid_sha(source_sha)
        || !crate::input::valid_sha(builder_sha)
        || !crate::input::valid_sha(base_sha)
        || !hash(inventory_sha256)
    {
        return Err("Invalid Source-CI metadata selection binding");
    }
    let root = format!("repos/{source_repo}");
    let source_repository = repository(&source.get_json(&root)?, source_repo, true)?;
    let (state, head_repository, head, base, merge) = if source_ref == "refs/heads/main" {
        let reference = source.get_json(&format!("{root}/git/ref/heads/main"))?;
        if reference["ref"] != "refs/heads/main" || reference["object"]["type"] != "commit" {
            return Err("Source-CI source ref changed");
        }
        let head = text(&reference["object"], "sha")?.to_owned();
        (
            "main".to_owned(),
            source_repo.to_owned(),
            head.clone(),
            head.clone(),
            head,
        )
    } else {
        let number = source_ref
            .strip_prefix("refs/pull/")
            .and_then(|s| s.strip_suffix("/head"))
            .ok_or("Invalid Source-CI pull ref")?;
        let pr = source.get_json(&format!("{root}/pulls/{number}"))?;
        if pr["state"] != "open"
            || pr["head"]["repo"]["full_name"] != source_repo
            || pr["head"]["repo"]["private"] != true
            || pr["base"]["repo"]["full_name"] != source_repo
            || pr["base"]["ref"] != "main"
        {
            return Err("Source-CI pull request origin denied");
        }
        let head = text(&pr["head"], "sha")?.to_owned();
        let base = text(&pr["base"], "sha")?.to_owned();
        if !crate::input::valid_sha(&head) || !crate::input::valid_sha(&base) {
            return Err("Invalid Source-CI pull request commit");
        }
        let compare = source.get_json(&format!("{root}/compare/{base}...{head}"))?;
        (
            "open".to_owned(),
            source_repo.to_owned(),
            head,
            base,
            text(&compare["merge_base_commit"], "sha")?.to_owned(),
        )
    };
    if head != source_sha || base != base_sha || merge != base {
        return Err("Source-CI source head or base changed");
    }
    let gitlink = source.get_json(&format!("{root}/contents/leapterm-release?ref={head}"))?;
    if let Some(entries) = gitlink.as_array() {
        if entries.is_empty() || entries.len() > 1024 {
            return Err("Source-CI builder gitlink changed");
        }
        for entry in entries {
            let entry_path = text(entry, "path")?;
            let entry_type = text(entry, "type")?;
            let entry_sha = text(entry, "sha")?;
            if !entry_path.starts_with("leapterm-release/")
                || !["file", "dir"].contains(&entry_type)
                || !crate::input::valid_sha(entry_sha)
            {
                return Err("Source-CI builder gitlink changed");
            }
        }
        let source_commit = source.get_json(&format!("{root}/git/commits/{head}"))?;
        if text(&source_commit, "sha")? != head {
            return Err("Source-CI builder gitlink changed");
        }
        let root_tree_sha = text(&source_commit["tree"], "sha")?;
        if !crate::input::valid_sha(root_tree_sha) {
            return Err("Source-CI builder gitlink changed");
        }
        let root_tree = source.get_json(&format!("{root}/git/trees/{root_tree_sha}"))?;
        if text(&root_tree, "sha")? != root_tree_sha || root_tree["truncated"] != false {
            return Err("Source-CI builder gitlink changed");
        }
        let tree_entries = root_tree["tree"]
            .as_array()
            .ok_or("Source-CI builder gitlink changed")?;
        let release_entries: Vec<_> = tree_entries
            .iter()
            .filter(|e| e["path"] == "leapterm-release")
            .collect();
        if release_entries.len() != 1
            || release_entries[0]["mode"] != "040000"
            || release_entries[0]["type"] != "tree"
        {
            return Err("Source-CI builder gitlink changed");
        }
        let source_subtree_sha = text(release_entries[0], "sha")?;
        if !crate::input::valid_sha(source_subtree_sha) {
            return Err("Source-CI builder gitlink changed");
        }
        let env = crate::clean_environment(&std::env::vars().collect());
        let builder_tree_sha = match crate::source::builder_tree_for_commit(builder_sha, None, &env)
        {
            Ok(tree_sha) => tree_sha,
            Err(_) => {
                let builder_commit = source.get_json(&format!(
                    "repos/{BUILDER_REPOSITORY}/git/commits/{builder_sha}"
                ))?;
                if text(&builder_commit, "sha")? != builder_sha {
                    return Err("Source-CI builder gitlink changed");
                }
                let tree_sha = text(&builder_commit["tree"], "sha")?;
                if !crate::input::valid_sha(tree_sha) {
                    return Err("Source-CI builder gitlink changed");
                }
                tree_sha.to_owned()
            }
        };
        if source_subtree_sha != builder_tree_sha {
            return Err("Source-CI builder gitlink changed");
        }
    } else if !["submodule", "file"].contains(&text(&gitlink, "type")?)
        || gitlink["submodule_git_url"] != crate::source::PUBLIC_URL
        || gitlink["sha"] != builder_sha
        || gitlink["path"] != "leapterm-release"
    {
        return Err("Source-CI builder gitlink changed");
    }
    let mapping = source.get_json(&format!(
        "{root}/contents/scripts/release/public-ci-migration.json?ref={head}"
    ))?;
    if mapping["type"] != "file"
        || mapping["encoding"] != "base64"
        || number(&mapping, "size")? > source_api::MAX_JSON as u64
    {
        return Err("Source-CI migration inventory unavailable");
    }
    let encoded = text(&mapping, "content")?;
    if encoded.len() > source_api::MAX_JSON * 2 {
        return Err("Source-CI inventory exceeds bound");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.replace(['\r', '\n'], ""))
        .map_err(|_| "Invalid Source-CI inventory encoding")?;
    if bytes.len() != number(&mapping, "size")? as usize || bytes.len() > source_api::MAX_JSON {
        return Err("Source-CI inventory size changed");
    }
    let mapping = crate::json::parse(&bytes)?;
    fields(
        &mapping,
        &["schema", "source_revision", "inventory_sha256", "jobs"],
    )?;
    if mapping["schema"] != 1
        || mapping["inventory_sha256"] != inventory_sha256
        || !mapping["jobs"]
            .as_array()
            .is_some_and(|j| !j.is_empty() && j.len() <= 4096)
    {
        return Err("Source-CI current inventory changed");
    }
    Ok(
        json!({"source_repository":source_repository,"source_ref":source_ref,"source_head_repository":head_repository,"source_state":state,
        "head_sha":head,"base_sha":base,"merge_base_sha":merge,"source_builder_sha":builder_sha}),
    )
}
pub fn subject_run(public: &mut dyn SourceApi, identity: &PipelineIdentity) -> Result<Value> {
    identity.validate()?;
    repository(
        &public.get_json(&format!("repos/{BUILDER_REPOSITORY}"))?,
        BUILDER_REPOSITORY,
        false,
    )?;
    let run = public.get_json(&format!(
        "repos/{BUILDER_REPOSITORY}/actions/runs/{}",
        identity.run_id
    ))?;
    if run["id"].as_u64().map(|v| v.to_string()).as_deref() != Some(&identity.run_id)
        || run["run_attempt"]
            .as_u64()
            .map(|v| v.to_string())
            .as_deref()
            != Some(&identity.attempt)
        || run["event"] != "workflow_dispatch"
        || run["head_branch"] != "main"
        || run["head_sha"] != identity.builder_sha
        || run["path"] != ".github/workflows/source-ci.yml"
        || run["repository"]["full_name"] != BUILDER_REPOSITORY
        || run["repository"]["private"] != false
        || run["head_repository"]["full_name"] != BUILDER_REPOSITORY
        || run["head_repository"]["fork"] != false
    {
        return Err("Source-CI public run identity changed");
    }
    Ok(run)
}
pub fn run_jobs(public: &mut dyn SourceApi, identity: &PipelineIdentity) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for page in 1..=source_api::MAX_PAGES {
        let value = public.get_json(&format!(
            "repos/{BUILDER_REPOSITORY}/actions/runs/{}/attempts/{}/jobs?per_page=100&page={page}",
            identity.run_id, identity.attempt
        ))?;
        let jobs = value["jobs"]
            .as_array()
            .ok_or("Source-CI job metadata unavailable")?;
        if jobs.len() > 100 {
            return Err("Source-CI jobs exceed page bound");
        }
        for job in jobs {
            if !seen.insert(number(job, "id")?)
                || job["run_id"].as_u64().map(|v| v.to_string()).as_deref()
                    != Some(&identity.run_id)
                || job["run_attempt"]
                    .as_u64()
                    .map(|v| v.to_string())
                    .as_deref()
                    != Some(&identity.attempt)
                || job["head_sha"] != identity.builder_sha
            {
                return Err("Source-CI job identity changed");
            }
            result.push(job.clone());
        }
        if jobs.len() < 100 {
            if number(&value, "total_count")? != result.len() as u64 {
                return Err("Source-CI job pagination incomplete");
            }
            return Ok(result);
        }
    }
    Err("Source-CI job pagination exceeds bound")
}
pub fn hosted_job(job: &Value) -> Result<()> {
    let labels = job["labels"]
        .as_array()
        .ok_or("Source-CI runner labels unavailable")?;
    if labels.len() != 1
        || !labels[0]
            .as_str()
            .is_some_and(|l| crate::runner_policy::RUNNERS.contains(&l))
        || job["runner_group_name"] != "GitHub Actions"
        || job["runner_name"].as_str().is_none_or(|s| s.is_empty())
    {
        return Err("Source-CI runner policy denied");
    }
    Ok(())
}
pub fn fresh_ci_observation(env: &Environment, request: &SourceCiRequest) -> Result<Value> {
    require_origin(env, "source-ci.yml", &["workflow_dispatch"])?;
    if env.get("GITHUB_SHA") != Some(&request.identity.builder_sha)
        || env.get("GITHUB_RUN_ID") != Some(&request.identity.run_id)
        || env.get("GITHUB_RUN_ATTEMPT") != Some(&request.identity.attempt)
    {
        return Err("Source-CI execution identity changed");
    }
    let work = tempfile::tempdir().map_err(|_| "Source-CI observation workspace unavailable")?;
    let mut public = GitHubApi::new(env, work.path(), Role::PublicRead)?;
    let mut protected = GitHubApi::new(env, work.path(), Role::ApprovalRead)?;
    let mut source = GitHubApi::new(env, work.path(), Role::SourceRead)?;
    let approval = acquire_approval(
        &mut public,
        &mut protected,
        &request.identity.run_id,
        &request.identity.attempt,
        source_api::now()?,
    )?;
    public.set_deadline(approval.expires_epoch)?;
    protected.set_deadline(approval.expires_epoch)?;
    source.set_deadline(approval.expires_epoch)?;
    if env.get("INPUT_CATALOG_SHA256") != Some(&approval.catalog_sha256) {
        return Err("Source-CI requested catalog changed");
    }
    let run = subject_run(&mut public, &request.identity)?;
    let jobs = run_jobs(&mut public, &request.identity)?;
    let name = format!("ci [{}]", request.stage);
    let active = jobs
        .iter()
        .filter(|j| {
            j["name"] == name
                && j["status"] == "in_progress"
                && j["runner_name"].as_str() == env.get("RUNNER_NAME").map(String::as_str)
        })
        .collect::<Vec<_>>();
    if active.len() != 1 || run["status"] != "in_progress" {
        return Err("Source-CI active runner unavailable");
    }
    hosted_job(active[0])?;
    let mut observed = fresh_source(&mut source, request, &approval)?;
    let map = observed
        .as_object_mut()
        .ok_or("Invalid Source-CI observation")?;
    for (name, value) in [
        (
            "execution_repository",
            json!({"full_name":BUILDER_REPOSITORY,"private":false,"default_branch":"main"}),
        ),
        ("github_actions", json!(true)),
        ("event_name", json!("workflow_dispatch")),
        ("execution_ref", json!("refs/heads/main")),
        ("workflow_ref", json!(ci_request::CI_WORKFLOW)),
        ("builder_sha", json!(request.identity.builder_sha)),
        ("run_id", json!(request.identity.run_id)),
        ("attempt", json!(request.identity.attempt)),
        ("approved_source_sha", json!(approval.identity.source_sha)),
        ("approved_builder_sha", json!(approval.identity.builder_sha)),
        ("approved_source_ref", json!(approval.source_ref)),
        ("approved_base_sha", json!(approval.base_sha)),
    ] {
        map.insert(name.into(), value);
    }
    ci_request::authorize_ci(request, &observed)?;
    Ok(observed)
}

pub fn select_candidates(metadata: &Value, prior: &Value) -> Result<Value> {
    fields(
        metadata,
        &["source_repository", "builder_repository", "candidates"],
    )?;
    let source_repo = text(&metadata["source_repository"], "full_name")?;
    if !crate::input::valid_repo_slug(source_repo) {
        return Err("Source-CI discovery repository denied");
    }
    repository(&metadata["source_repository"], source_repo, true)?;
    repository(&metadata["builder_repository"], BUILDER_REPOSITORY, false)?;
    fields(prior, &["runs"])?;
    let prior = prior["runs"]
        .as_array()
        .ok_or("Invalid Source-CI prior runs")?;
    let candidates = metadata["candidates"]
        .as_array()
        .ok_or("Invalid Source-CI discovery metadata")?;
    if candidates.len() > 64 || prior.len() > 1000 {
        return Err("Source-CI discovery exceeds bound");
    }
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for row in candidates {
        fields(
            row,
            &[
                "source_ref",
                "source_sha",
                "base_sha",
                "builder_sha",
                "catalog_sha256",
                "workflow_inventory_sha256",
                "head_repository",
                "state",
            ],
        )?;
        let reference = text(row, "source_ref")?;
        if !ci_request::valid_source_ref(reference)
            || !crate::input::valid_sha(text(row, "source_sha")?)
            || !crate::input::valid_sha(text(row, "base_sha")?)
            || !crate::input::valid_sha(text(row, "builder_sha")?)
            || !hash(text(row, "catalog_sha256")?)
            || !hash(text(row, "workflow_inventory_sha256")?)
            || row["head_repository"] != source_repo
            || (reference == "refs/heads/main"
                && (row["state"] != "main" || row["base_sha"] != row["source_sha"]))
            || (reference != "refs/heads/main" && row["state"] != "open")
        {
            return Err("Source-CI discovery candidate denied");
        }
        let source_sha = text(row, "source_sha")?;
        let builder_sha = text(row, "builder_sha")?;
        let catalog_sha256 = text(row, "catalog_sha256")?;
        let cid = correlation_id(source_repo, source_sha, builder_sha, "ci");
        let stage_cid = correlation_id(source_repo, source_sha, builder_sha, "source");
        let key = format!("{source_sha}:{builder_sha}:{catalog_sha256}:ci");
        if !seen.insert(key) {
            return Err("Duplicate Source-CI discovery candidate");
        }
        if prior.iter().any(|r| {
            r["mode"] == "ci"
                && r["builder_sha"] == row["builder_sha"]
                && (r["correlation_id"].as_str() == Some(cid.as_str())
                    || r["correlation_id"].as_str() == Some(stage_cid.as_str())
                    || (r["source_sha"] == row["source_sha"]
                        && r["catalog_sha256"] == row["catalog_sha256"]))
        }) {
            continue;
        }
        selected.push(json!({"source_ref":row["source_ref"],"source_sha":row["source_sha"],"builder_sha":row["builder_sha"],"catalog_sha256":row["catalog_sha256"],"correlation_id":cid,"mode":"ci"}));
    }
    Ok(json!({"candidates":selected}))
}
fn recorded_runs(public: &mut dyn SourceApi) -> Result<Value> {
    let mut rows = Vec::new();
    let mut ids = BTreeSet::new();
    for page in 1..=source_api::MAX_PAGES {
        let data=public.get_json(&format!("repos/{BUILDER_REPOSITORY}/actions/workflows/source-ci.yml/runs?event=workflow_dispatch&branch=main&per_page=100&page={page}"))?;
        let runs = data["workflow_runs"]
            .as_array()
            .ok_or("Source-CI discovery runs unavailable")?;
        if runs.len() > 100 {
            return Err("Source-CI discovery page exceeds bound");
        }
        for run in runs {
            if !ids.insert(number(run, "id")?)
                || run["event"] != "workflow_dispatch"
                || run["head_branch"] != "main"
                || run["repository"]["full_name"] != BUILDER_REPOSITORY
            {
                return Err("Invalid Source-CI discovery run");
            }
            let title = text(run, "display_title")?;
            let head_sha = text(run, "head_sha")?;
            if let Some(cid) = title.strip_prefix("source-ci:")
                && valid_correlation_id(cid)
                && crate::input::valid_sha(head_sha)
            {
                rows.push(json!({"correlation_id":cid,"builder_sha":head_sha,"mode":"ci"}));
            }
        }
        if runs.len() < 100 {
            if number(&data, "total_count")? > ids.len() as u64 {
                return Err("Source-CI discovery pagination incomplete");
            }
            return Ok(json!({"runs":rows}));
        }
    }
    Err("Source-CI discovery pagination exceeds bound")
}
pub fn discover_cli(args: &[String], env: &Environment) -> Result<()> {
    if !args.is_empty() {
        return Err("Unexpected Source-CI discovery arguments");
    }
    require_origin(
        env,
        "source-discovery.yml",
        &["schedule", "workflow_dispatch"],
    )?;
    if env.get("SOURCE_CI_DISCOVERY_ENABLED").map(String::as_str) != Some("true") {
        return Err("Source-CI discovery is disabled");
    }
    let source_repo = env
        .get("SOURCE_REPOSITORY")
        .map(String::as_str)
        .filter(|s| crate::input::valid_repo_slug(s))
        .ok_or("Source-CI discovery source repository missing")?;
    let work = tempfile::tempdir().map_err(|_| "Source-CI discovery workspace unavailable")?;
    let mut public = GitHubApi::new(env, work.path(), Role::Dispatch)?;
    let mut protected = GitHubApi::new(env, work.path(), Role::ApprovalRead)?;
    let mut source = GitHubApi::new(env, work.path(), Role::SourceRead)?;
    let config = protected.get_json(&format!(
        "repos/{BUILDER_REPOSITORY}/environments/source-ci-discovery/variables/SOURCE_CI_DISCOVERY"
    ))?;
    if config["name"] != "SOURCE_CI_DISCOVERY" {
        return Err("Source-CI discovery configuration changed");
    }
    let raw = text(&config, "value")?;
    if raw.len() > 65536 {
        return Err("Source-CI discovery configuration exceeds bound");
    }
    let config = crate::json::parse(raw.as_bytes())?;
    fields(
        &config,
        &[
            "schema",
            "builder_sha",
            "not_before_epoch",
            "expires_epoch",
            "candidates",
        ],
    )?;
    let now = source_api::now()?;
    if config["schema"] != "leapterm.source-ci.discovery.v1"
        || !crate::input::valid_sha(text(&config, "builder_sha")?)
        || number(&config, "not_before_epoch")? > now
        || number(&config, "expires_epoch")? <= now
        || number(&config, "expires_epoch")?.saturating_sub(number(&config, "not_before_epoch")?)
            > 86400
    {
        return Err("Source-CI discovery configuration expired");
    }
    public.set_deadline(number(&config, "expires_epoch")?)?;
    protected.set_deadline(number(&config, "expires_epoch")?)?;
    source.set_deadline(number(&config, "expires_epoch")?)?;
    let builder = public.get_json(&format!("repos/{BUILDER_REPOSITORY}/git/ref/heads/main"))?;
    if builder["ref"] != "refs/heads/main"
        || builder["object"]["sha"] != config["builder_sha"]
        || env.get("GITHUB_SHA").map(String::as_str) != config["builder_sha"].as_str()
    {
        return Err("Source-CI discovery builder changed");
    }
    let candidates = config["candidates"]
        .as_array()
        .ok_or("Invalid Source-CI selection configuration")?;
    if candidates.is_empty() || candidates.len() > 64 {
        return Err("Source-CI selection exceeds bound");
    }
    let mut current = Vec::new();
    for row in candidates {
        fields(
            row,
            &[
                "source_ref",
                "source_sha",
                "base_sha",
                "catalog_sha256",
                "workflow_inventory_sha256",
            ],
        )?;
        if !hash(text(row, "catalog_sha256")?) {
            return Err("Invalid Source-CI selected catalog digest");
        }
        let observation = fresh_binding(
            &mut source,
            source_repo,
            text(row, "source_ref")?,
            text(row, "source_sha")?,
            text(&config, "builder_sha")?,
            text(row, "base_sha")?,
            text(row, "workflow_inventory_sha256")?,
        )?;
        current.push(json!({"source_ref":row["source_ref"],"source_sha":row["source_sha"],"base_sha":row["base_sha"],"builder_sha":config["builder_sha"],"catalog_sha256":row["catalog_sha256"],"workflow_inventory_sha256":row["workflow_inventory_sha256"],"head_repository":observation["source_head_repository"],"state":observation["source_state"]}));
    }
    let metadata = json!({"source_repository":repository(&source.get_json(&format!("repos/{source_repo}"))?,source_repo,true)?,"builder_repository":repository(&public.get_json(&format!("repos/{BUILDER_REPOSITORY}"))?,BUILDER_REPOSITORY,false)?,"candidates":current});
    let selected = select_candidates(&metadata, &recorded_runs(&mut public)?)?;
    for candidate in selected["candidates"]
        .as_array()
        .ok_or("Invalid Source-CI selection")?
    {
        let one = json!({"source_repository":metadata["source_repository"],"builder_repository":metadata["builder_repository"],"candidates":metadata["candidates"].as_array().ok_or("Invalid Source-CI metadata")?.iter().filter(|r|r["source_sha"]==candidate["source_sha"]).cloned().collect::<Vec<_>>()});
        if select_candidates(&one, &recorded_runs(&mut public)?)?["candidates"] == json!([]) {
            continue;
        }
        let binding = one["candidates"]
            .as_array()
            .and_then(|r| r.first())
            .ok_or("Source-CI selected binding unavailable")?;
        fresh_binding(
            &mut source,
            source_repo,
            text(binding, "source_ref")?,
            text(binding, "source_sha")?,
            text(binding, "builder_sha")?,
            text(binding, "base_sha")?,
            text(binding, "workflow_inventory_sha256")?,
        )?;
        let builder = public.get_json(&format!("repos/{BUILDER_REPOSITORY}/git/ref/heads/main"))?;
        if builder["object"]["sha"] != config["builder_sha"]
            || source_api::now()? >= number(&config, "expires_epoch")?
        {
            return Err("Source-CI discovery binding expired before dispatch");
        }
        let result=public.post_json(&format!("repos/{BUILDER_REPOSITORY}/actions/workflows/source-ci.yml/dispatches"),&json!({"ref":"main","inputs":{"source_sha":candidate["source_sha"],"source_ref":candidate["source_ref"],"builder_sha":candidate["builder_sha"],"catalog_sha256":candidate["catalog_sha256"],"correlation_id":candidate["correlation_id"]}}));
        if result.is_err()
            && select_candidates(&one, &recorded_runs(&mut public)?)?["candidates"] != json!([])
        {
            return Err("Source-CI dispatch acceptance is unresolved; retry denied");
        }
    }
    println!("Source-CI metadata discovery completed.");
    Ok(())
}
