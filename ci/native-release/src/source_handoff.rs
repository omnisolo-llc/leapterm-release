//! Source CI uploads one fixed, classified private receipt and its generic
//! envelope. Neither a path, role declaration, encryption key, nor storage
//! configuration grants authority to upload other data. No deletion exists.
use crate::{
    Environment, Result,
    ci_request::{CI_STAGES, PipelineIdentity, SOURCE_REPOSITORY, SourceCiRequest},
    guards,
    source_api::{
        self, GitHubApi, Role, SourceApi, digest, fields, hash, json_digest, number, text,
    },
    source_discovery::{Approval, acquire_approval, fresh_ci_observation, request_digest},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::Read, path::Path};

const COUNTERS: [&str; 6] = [
    "expected",
    "registered",
    "executed",
    "passed",
    "failed",
    "skipped",
];
fn passed_counts(value: &Value) -> Result<u64> {
    let expected = number(value, "expected")?;
    if expected == 0
        || expected > 1_000_000
        || value["status"] != "passed"
        || number(value, "registered")? != expected
        || number(value, "executed")? != expected
        || number(value, "passed")? != expected
        || number(value, "failed")? != 0
        || number(value, "skipped")? != 0
    {
        return Err("Source-CI required case accounting is incomplete");
    }
    Ok(expected)
}
fn input_hashes(value: &Value) -> Result<&serde_json::Map<String, Value>> {
    let inputs = value
        .as_object()
        .ok_or("Source-CI input digests must retain their file identities")?;
    if inputs.is_empty()
        || inputs.len() > 4096
        || inputs.iter().any(|(path, digest)| {
            !guards::safe_path(path)
                || path.len() > 512
                || path.split('/').any(|component| {
                    component == ".git" || component == ".env" || component.starts_with(".env.")
                })
                || !digest.as_str().is_some_and(hash)
        })
    {
        return Err("Invalid Source-CI receipt inputs");
    }
    Ok(inputs)
}
pub fn verify_stage_receipt(
    value: &Value,
    request: &SourceCiRequest,
    approval: &Approval,
) -> Result<Value> {
    fields(
        value,
        &[
            "schema",
            "request",
            "catalog_sha256",
            "inputs",
            "suites",
            "case_ids_sha256",
            "expected",
            "registered",
            "executed",
            "passed",
            "failed",
            "skipped",
            "status",
        ],
    )?;
    let approved = approval.stage(request)?;
    if value["schema"] != "omniterm.source-ci.stage.v1"
        || SourceCiRequest::parse(&value["request"])? != *request
        || value["catalog_sha256"] != approval.catalog_sha256
    {
        return Err("Source-CI stage receipt identity changed");
    }
    let inputs = input_hashes(&value["inputs"])?;
    let suites = value["suites"]
        .as_array()
        .ok_or("Source-CI suite receipts unavailable")?;
    if suites.is_empty() || suites.len() > 4096 {
        return Err("Source-CI suite receipt count exceeds bound");
    }
    let mut suite_ids = BTreeSet::new();
    let mut cases = BTreeSet::new();
    let mut expected = 0u64;
    for suite in suites {
        fields(
            suite,
            &[
                "id",
                "kind",
                "command_sha256",
                "input_sha256",
                "case_ids",
                "case_ids_sha256",
                "expected",
                "registered",
                "executed",
                "passed",
                "failed",
                "skipped",
                "status",
            ],
        )?;
        let id = text(suite, "id")?;
        if id.len() > 256
            || !id.starts_with(&format!("{}:", request.stage))
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
            || !suite_ids.insert(id)
            || ![
                "command",
                "rust",
                "flutter",
                "node",
                "playwright",
                "relay",
                "junit",
            ]
            .contains(&text(suite, "kind")?)
            || !hash(text(suite, "command_sha256")?)
        {
            return Err("Invalid Source-CI owning suite receipt");
        }
        let suite_inputs = input_hashes(&suite["input_sha256"])?;
        if !inputs
            .iter()
            .all(|(path, digest)| suite_inputs.get(path) == Some(digest))
        {
            return Err("Source-CI suite changed its stage input identities");
        }
        let registered = suite["case_ids"]
            .as_array()
            .ok_or("Source-CI registered cases unavailable")?;
        let count = passed_counts(suite)?;
        if registered.len() != count as usize
            || json_digest(&suite["case_ids"])? != text(suite, "case_ids_sha256")?
        {
            return Err("Source-CI inner case inventory changed");
        }
        let mut previous = None;
        for case in registered {
            let case = case.as_str().ok_or("Invalid Source-CI case id")?;
            if case.len() > id.len() + 2 + 2048
                || !case.starts_with(&format!("{id}::"))
                || case.len() <= id.len() + 2
                || case.chars().any(char::is_control)
                || previous.is_some_and(|p| p >= case)
                || !cases.insert(case.to_owned())
            {
                return Err("Source-CI case inventory is not an exact partition");
            }
            previous = Some(case);
        }
        expected = expected
            .checked_add(count)
            .ok_or("Source-CI case counters exceed bound")?;
    }
    let cases = cases.into_iter().collect::<Vec<_>>();
    if passed_counts(value)? != expected
        || expected != cases.len() as u64
        || json_digest(&json!(cases))? != text(value, "case_ids_sha256")?
        || value["case_ids_sha256"] != approved.case_ids_sha256
    {
        return Err("Source-CI approved cases are incomplete");
    }
    Ok(
        json!({"expected":expected,"registered":expected,"executed":expected,"passed":expected,"failed":0,"skipped":0,"status":"passed","case_ids_sha256":value["case_ids_sha256"]}),
    )
}
fn names(request: &SourceCiRequest) -> (String, String) {
    let base = format!(
        "source-ci-{}-{}-of-{}",
        request.stage, request.shard_index, request.shard_count
    );
    (format!("{base}.json"), format!("{base}.handoff.json"))
}
fn allowed_name(name: &str) -> bool {
    CI_STAGES.iter().any(|stage| {
        name == format!("source-ci-{stage}-0-of-1.json")
            || name == format!("source-ci-{stage}-0-of-1.handoff.json")
    })
}
pub fn verify_handoff_metadata(value: &Value, identity: &Value, stage: &str) -> Result<()> {
    fields(
        value,
        &[
            "schema",
            "purpose",
            "identity",
            "source_ref",
            "stage",
            "shard_index",
            "shard_count",
            "request_sha256",
            "approval_sha256",
            "catalog_sha256",
            "case_ids_sha256",
            "expires_epoch",
            "status",
            "expected",
            "registered",
            "executed",
            "passed",
            "failed",
            "skipped",
            "receipt",
        ],
    )?;
    let id = PipelineIdentity::parse(identity)?;
    if value["schema"] != 1
        || value["purpose"] != "source-ci-stage-handoff"
        || PipelineIdentity::parse(&value["identity"])? != id
        || value["stage"] != stage
        || !CI_STAGES.contains(&stage)
        || value["shard_index"] != 0
        || value["shard_count"] != 1
    {
        return Err("Source-CI handoff identity changed");
    }
    let request = SourceCiRequest::parse(
        &json!({"identity":identity,"source_ref":value["source_ref"],"stage":stage,"shard_index":value["shard_index"],"shard_count":value["shard_count"]}),
    )?;
    if value["request_sha256"] != request_digest(&request)?
        || [
            "request_sha256",
            "approval_sha256",
            "catalog_sha256",
            "case_ids_sha256",
        ]
        .iter()
        .any(|k| !value[k].as_str().is_some_and(hash))
        || number(value, "expires_epoch")? == 0
    {
        return Err("Invalid Source-CI handoff binding");
    }
    passed_counts(value)?;
    let receipt = &value["receipt"];
    fields(receipt, &["name", "size", "sha256", "role"])?;
    if receipt["role"] != "private-evidence"
        || receipt["name"] != names(&request).0
        || !hash(text(receipt, "sha256")?)
        || number(receipt, "size")? == 0
        || number(receipt, "size")? > source_api::MAX_RECEIPT as u64
    {
        return Err("Source-CI handoff classification denied");
    }
    Ok(())
}
fn read_receipt(path: &Path) -> Result<Vec<u8>> {
    if path.file_name().and_then(|p| p.to_str()) != Some("source-ci-stage.json") {
        return Err("Source-CI uploader accepts only its stage receipt");
    }
    guards::directory(
        path.parent()
            .ok_or("Source-CI receipt parent unavailable")?,
    )?;
    let mut file = guards::open_regular(path, source_api::MAX_RECEIPT as u64)?;
    let before = file
        .metadata()
        .map_err(|_| "Source-CI receipt unavailable")?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(source_api::MAX_RECEIPT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Source-CI receipt unavailable")?;
    if bytes.len() != before.len() as usize || bytes.len() > source_api::MAX_RECEIPT {
        return Err("Source-CI receipt changed");
    }
    guards::unchanged(&file, path)?;
    if !guards::same(
        &before,
        &file
            .metadata()
            .map_err(|_| "Source-CI receipt unavailable")?,
    ) {
        return Err("Source-CI receipt changed");
    }
    Ok(bytes)
}
fn marker(approval: &Approval) -> Result<Value> {
    Ok(
        json!({"schema":1,"purpose":"private-source-ci-handoff","identity":approval.identity,"approval_sha256":approval.digest()?,"catalog_sha256":approval.catalog_sha256}),
    )
}
fn require_private(api: &mut dyn SourceApi) -> Result<()> {
    let repo = api.get_json(&format!("repos/{SOURCE_REPOSITORY}"))?;
    if repo["full_name"] != SOURCE_REPOSITORY || repo["private"] != true {
        return Err("Source-CI handoff repository is not private");
    }
    Ok(())
}
fn candidate(api: &mut dyn SourceApi, approval: &Approval) -> Result<Option<u64>> {
    require_private(api)?;
    let tag = format!(
        "ci-stage/ci-{}-{}",
        approval.identity.run_id, approval.identity.attempt
    );
    let expected = marker(approval)?;
    let mut found = None;
    let mut seen = BTreeSet::new();
    for page in 1..=source_api::MAX_PAGES {
        let releases = api.get_json(&format!(
            "repos/{SOURCE_REPOSITORY}/releases?per_page=100&page={page}"
        ))?;
        let releases = releases
            .as_array()
            .ok_or("Source-CI candidate releases unavailable")?;
        if releases.len() > 100 {
            return Err("Source-CI release page exceeds bound");
        }
        for release in releases {
            let id = number(release, "id")?;
            if id == 0 || !seen.insert(id) {
                return Err("Source-CI release pagination changed");
            }
            if release["tag_name"] != tag {
                continue;
            }
            let body = text(release, "body")?;
            if body.len() > source_api::MAX_ENVELOPE
                || release["draft"] != true
                || release["target_commitish"] != approval.identity.source_sha
                || crate::json::parse(body.as_bytes())? != expected
                || found.replace(id).is_some()
            {
                return Err("Source-CI candidate draft identity changed");
            }
        }
        if releases.len() < 100 {
            return Ok(found);
        }
    }
    Err("Source-CI release pagination exceeds bound")
}
fn assets(api: &mut dyn SourceApi, release: u64) -> Result<Vec<Value>> {
    require_private(api)?;
    let mut result = Vec::new();
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for page in 1..=source_api::MAX_PAGES {
        let rows = api.get_json(&format!(
            "repos/{SOURCE_REPOSITORY}/releases/{release}/assets?per_page=100&page={page}"
        ))?;
        let rows = rows.as_array().ok_or("Source-CI assets unavailable")?;
        if rows.len() > 100 {
            return Err("Source-CI asset page exceeds bound");
        }
        for row in rows {
            let name = text(row, "name")?;
            if number(row, "id")? == 0
                || !ids.insert(number(row, "id")?)
                || !names.insert(name.to_owned())
                || !allowed_name(name)
                || row["state"] != "uploaded"
                || number(row, "size")? == 0
                || number(row, "size")? > source_api::MAX_RECEIPT as u64
                || (name.ends_with(".handoff.json")
                    && number(row, "size")? > source_api::MAX_ENVELOPE as u64)
            {
                return Err("Source-CI stage asset inventory denied");
            }
            result.push(row.clone());
            if result.len() > CI_STAGES.len() * 2 {
                return Err("Source-CI asset inventory exceeds bound");
            }
        }
        if rows.len() < 100 {
            return Ok(result);
        }
    }
    Err("Source-CI asset pagination exceeds bound")
}
fn download(
    api: &mut dyn SourceApi,
    asset: &Value,
    expected_size: u64,
    expected_hash: &str,
    max: usize,
) -> Result<Vec<u8>> {
    require_private(api)?;
    if number(asset, "size")? != expected_size
        || asset["label"] != format!("v1:{expected_hash}:{expected_size}")
    {
        return Err("Source-CI retained asset metadata changed");
    }
    let bytes = api.get_bytes(
        &format!(
            "repos/{SOURCE_REPOSITORY}/releases/assets/{}",
            number(asset, "id")?
        ),
        max,
    )?;
    if bytes.len() as u64 != expected_size || digest(&bytes) != expected_hash {
        return Err("Source-CI retained asset bytes changed");
    }
    Ok(bytes)
}
fn put_once(
    api: &mut dyn SourceApi,
    approval: &Approval,
    release: u64,
    name: &str,
    bytes: &[u8],
    max: usize,
) -> Result<()> {
    if !allowed_name(name) || bytes.is_empty() || bytes.len() > max {
        return Err("Source-CI stage upload denied");
    }
    let existing = assets(api, release)?;
    let expected = digest(bytes);
    if let Some(asset) = existing.iter().find(|a| a["name"] == name) {
        download(api, asset, bytes.len() as u64, &expected, max)?;
        return Ok(());
    }
    if existing.len() >= CI_STAGES.len() * 2 || candidate(api, approval)? != Some(release) {
        return Err("Source-CI candidate upload identity changed");
    }
    require_private(api)?;
    let label = source_api::encode(&format!("v1:{expected}:{}", bytes.len()));
    let upload=api.upload(&format!("https://uploads.github.com/repos/{SOURCE_REPOSITORY}/releases/{release}/assets?name={name}&label={label}"),bytes);
    // POST can be accepted despite a lost response. Resolve once with fresh
    // metadata and downloaded bytes; never overwrite or blindly retry it.
    let rows = assets(api, release)?;
    let asset = rows
        .iter()
        .find(|a| a["name"] == name)
        .ok_or(if upload.is_err() {
            "Source-CI upload acceptance is unresolved"
        } else {
            "Source-CI upload readback is missing"
        })?;
    download(api, asset, bytes.len() as u64, &expected, max)?;
    if candidate(api, approval)? != Some(release) {
        return Err("Source-CI candidate changed during readback");
    }
    Ok(())
}
pub fn retain_stage_with(
    api: &mut dyn SourceApi,
    approval: &Approval,
    request: &SourceCiRequest,
    path: &Path,
) -> Result<()> {
    let bytes = read_receipt(path)?;
    let receipt = crate::json::parse(&bytes)?;
    let summary = verify_stage_receipt(&receipt, request, approval)?;
    let (name, envelope_name) = names(request);
    let mut envelope = json!({"schema":1,"purpose":"source-ci-stage-handoff","identity":request.identity,"source_ref":request.source_ref,"stage":request.stage,
        "shard_index":request.shard_index,"shard_count":request.shard_count,"request_sha256":request_digest(request)?,"approval_sha256":approval.digest()?,
        "catalog_sha256":approval.catalog_sha256,"case_ids_sha256":summary["case_ids_sha256"],"expires_epoch":approval.expires_epoch,"status":"passed",
        "receipt":{"name":name,"size":bytes.len(),"sha256":digest(&bytes),"role":"private-evidence"}});
    for counter in COUNTERS {
        envelope[counter] = summary[counter].clone();
    }
    verify_handoff_metadata(
        &envelope,
        &serde_json::to_value(&request.identity)
            .map_err(|_| "Invalid Source-CI identity encoding")?,
        &request.stage,
    )?;
    let release = if let Some(id) = candidate(api, approval)? {
        id
    } else {
        require_private(api)?;
        let tag = format!(
            "ci-stage/ci-{}-{}",
            request.identity.run_id, request.identity.attempt
        );
        let result=api.post_json(&format!("repos/{SOURCE_REPOSITORY}/releases"),&json!({"tag_name":tag,"name":tag,"target_commitish":request.identity.source_sha,"draft":true,"prerelease":true,"body":marker(approval)?.to_string(),"make_latest":"false"}));
        candidate(api, approval)?.ok_or(if result.is_err() {
            "Source-CI candidate creation acceptance is unresolved"
        } else {
            "Source-CI candidate creation readback is missing"
        })?
    };
    put_once(
        api,
        approval,
        release,
        &name,
        &bytes,
        source_api::MAX_RECEIPT,
    )?;
    let bytes = serde_json::to_vec(&envelope).map_err(|_| "Invalid Source-CI envelope encoding")?;
    put_once(
        api,
        approval,
        release,
        &envelope_name,
        &bytes,
        source_api::MAX_ENVELOPE,
    )?;
    Ok(())
}
pub fn retain_stage(env: &Environment, request: &SourceCiRequest, path: &Path) -> Result<()> {
    fresh_ci_observation(env, request)?;
    let work = tempfile::tempdir().map_err(|_| "Source-CI uploader workspace unavailable")?;
    let mut public = GitHubApi::new(env, work.path(), Role::PublicRead)?;
    let mut protected = GitHubApi::new(env, work.path(), Role::ApprovalRead)?;
    let approval = acquire_approval(
        &mut public,
        &mut protected,
        &request.identity.run_id,
        &request.identity.attempt,
        source_api::now()?,
    )?;
    let mut writer = GitHubApi::new(env, work.path(), Role::HandoffWrite)?;
    writer.set_deadline(approval.expires_epoch)?;
    retain_stage_with(&mut writer, &approval, request, path)
}
pub fn read_handoffs(api: &mut dyn SourceApi, approval: &Approval) -> Result<Vec<Value>> {
    let Some(release) = candidate(api, approval)? else {
        return Ok(Vec::new());
    };
    let inventory = assets(api, release)?;
    let mut verified = Vec::new();
    for approved in &approval.requests {
        let request = SourceCiRequest {
            identity: approval.identity.clone(),
            source_ref: approval.source_ref.clone(),
            stage: approved.stage.clone(),
            shard_index: approved.shard_index,
            shard_count: approved.shard_count,
        };
        let (name, envelope_name) = names(&request);
        let Some(asset) = inventory.iter().find(|a| a["name"] == envelope_name) else {
            continue;
        };
        let label = text(asset, "label")?;
        let parts = label.split(':').collect::<Vec<_>>();
        if parts.len() != 3
            || parts[0] != "v1"
            || !hash(parts[1])
            || parts[2] != number(asset, "size")?.to_string()
        {
            return Err("Invalid Source-CI envelope storage marker");
        }
        let bytes = download(
            api,
            asset,
            number(asset, "size")?,
            parts[1],
            source_api::MAX_ENVELOPE,
        )?;
        let envelope = crate::json::parse(&bytes)?;
        verify_handoff_metadata(
            &envelope,
            &serde_json::to_value(&approval.identity)
                .map_err(|_| "Invalid Source-CI identity encoding")?,
            &request.stage,
        )?;
        if envelope["approval_sha256"] != approval.digest()?
            || envelope["catalog_sha256"] != approval.catalog_sha256
            || envelope["source_ref"] != approval.source_ref
            || envelope["case_ids_sha256"] != approved.case_ids_sha256
            || envelope["expires_epoch"] != approval.expires_epoch
        {
            return Err("Source-CI retained approval changed");
        }
        let receipt = &envelope["receipt"];
        let asset = inventory
            .iter()
            .find(|a| a["name"] == name)
            .ok_or("Source-CI inner receipt is missing")?;
        let bytes = download(
            api,
            asset,
            number(receipt, "size")?,
            text(receipt, "sha256")?,
            source_api::MAX_RECEIPT,
        )?;
        let summary = verify_stage_receipt(&crate::json::parse(&bytes)?, &request, approval)?;
        for key in COUNTERS.into_iter().chain(["status", "case_ids_sha256"]) {
            if envelope[key] != summary[key] {
                return Err("Source-CI envelope changed its owning proof");
            }
        }
        verified.push(envelope);
    }
    if candidate(api, approval)? != Some(release) {
        return Err("Source-CI candidate changed during reporting");
    }
    Ok(verified)
}

/// Offline plan only. An eventual executor must recheck every marker, asset,
/// reference and run immediately before deletion. Unknown and live attempts
/// are preserved; this module exposes no deletion API or automatic cleanup.
pub fn cleanup_candidates(metadata: &Value, now_epoch: u64) -> Result<Value> {
    fields(metadata, &["repository", "observed_epoch", "releases"])?;
    if metadata["repository"]["full_name"] != SOURCE_REPOSITORY
        || metadata["repository"]["private"] != true
        || number(metadata, "observed_epoch")? != now_epoch
    {
        return Err("Source-CI cleanup observation is stale or foreign");
    }
    let releases = metadata["releases"]
        .as_array()
        .ok_or("Source-CI cleanup inventory unavailable")?;
    if releases.len() > 1000 {
        return Err("Source-CI cleanup inventory exceeds bound");
    }
    let mut deletions = Vec::new();
    let mut ids = BTreeSet::new();
    for release in releases {
        let Some(id) = release["id"].as_u64().filter(|id| *id > 0) else {
            continue;
        };
        if !ids.insert(id) {
            return Err("Duplicate Source-CI cleanup release");
        }
        if release["draft"] != true || release["referenced"] != false {
            continue;
        }
        let Some(body) = release["body"]
            .as_str()
            .filter(|b| b.len() <= source_api::MAX_ENVELOPE)
        else {
            continue;
        };
        let Ok(marker) = crate::json::parse(body.as_bytes()) else {
            continue;
        };
        if fields(
            &marker,
            &[
                "schema",
                "purpose",
                "identity",
                "approval_sha256",
                "catalog_sha256",
            ],
        )
        .is_err()
            || marker["schema"] != 1
            || marker["purpose"] != "private-source-ci-handoff"
            || !marker["approval_sha256"].as_str().is_some_and(hash)
            || !marker["catalog_sha256"].as_str().is_some_and(hash)
        {
            continue;
        }
        let Ok(identity) = PipelineIdentity::parse(&marker["identity"]) else {
            continue;
        };
        let tag = format!("ci-stage/ci-{}-{}", identity.run_id, identity.attempt);
        if release["tag_name"] != tag || release["target_commitish"] != identity.source_sha {
            continue;
        }
        let run = &release["run"];
        if run["id"] != identity.run_id
            || run["attempt"] != identity.attempt
            || run["status"] != "completed"
            || ![
                "success",
                "failure",
                "cancelled",
                "timed_out",
                "action_required",
                "startup_failure",
            ]
            .contains(&run["conclusion"].as_str().unwrap_or(""))
        {
            continue;
        }
        let Some(completed) = run["completed_epoch"].as_u64() else {
            continue;
        };
        let Some(created) = release["created_epoch"].as_u64() else {
            continue;
        };
        if created > completed || now_epoch.saturating_sub(completed) < 7 * 24 * 60 * 60 {
            continue;
        }
        let Some(assets) = release["assets"].as_array() else {
            continue;
        };
        if assets.len() > CI_STAGES.len() * 2
            || assets.iter().any(|a| {
                !a["name"].as_str().is_some_and(allowed_name)
                    || a["state"] != "uploaded"
                    || !a["size"]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= source_api::MAX_RECEIPT as u64)
            })
        {
            continue;
        }
        deletions.push(json!({"repository":SOURCE_REPOSITORY,"release_id":id,"tag_name":tag,"identity":identity,"marker_sha256":digest(body.as_bytes())}));
    }
    Ok(json!({"deletions":deletions}))
}
