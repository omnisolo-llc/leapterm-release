//! The independent reporter executes only trusted public builder code. Its
//! private status capability never reaches source checkout or build processes;
//! successful status requires fresh run metadata and actual verified bytes.
use crate::{
    Environment, Result,
    ci_request::{BUILDER_REPOSITORY, CI_STAGES, SOURCE_REPOSITORY, SourceCiRequest},
    source_api::{self, GitHubApi, Role, SourceApi, fields, text},
    source_discovery::{
        acquire_approval, fresh_source, hosted_job, require_origin, run_jobs, subject_run,
    },
    source_handoff::{read_handoffs, verify_handoff_metadata},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const CONTEXT: &str = "omniterm/public-source-ci";
/// Decision layer only. The runtime reporter below acquires and verifies the
/// inputs itself; a workflow_run file, artifact name, or candidate JSON cannot
/// be used as authorization to write this result.
pub fn source_status(run: &Value, handoffs: &[Value], request: &SourceCiRequest) -> Result<Value> {
    SourceCiRequest::parse(
        &serde_json::to_value(request).map_err(|_| "Invalid Source-CI report request")?,
    )?;
    fields(
        run,
        &[
            "identity",
            "source_ref",
            "catalog_sha256",
            "status",
            "conclusion",
            "jobs",
        ],
    )?;
    let identity =
        serde_json::to_value(&request.identity).map_err(|_| "Invalid Source-CI report identity")?;
    if run["identity"] != identity
        || run["source_ref"] != request.source_ref
        || !run["catalog_sha256"].as_str().is_some_and(source_api::hash)
    {
        return Err("Source-CI report run identity changed");
    }
    let status = text(run, "status")?;
    if ![
        "queued",
        "requested",
        "waiting",
        "pending",
        "in_progress",
        "completed",
    ]
    .contains(&status)
    {
        return Err("Invalid Source-CI report run status");
    }
    let mut complete = status == "completed" && run["conclusion"] == "success";
    let jobs = run["jobs"]
        .as_array()
        .ok_or("Source-CI report jobs unavailable")?;
    if jobs.len() > 1000 || handoffs.len() > CI_STAGES.len() {
        return Err("Source-CI report exceeds bound");
    }
    let mut names = BTreeSet::new();
    let expected_names = std::iter::once("policy".to_owned())
        .chain(CI_STAGES.iter().map(|s| format!("ci [{s}]")))
        .collect::<BTreeSet<_>>();
    for job in jobs {
        fields(job, &["name", "status", "conclusion"])?;
        let name = text(job, "name")?;
        if !names.insert(name.to_owned()) {
            return Err("Duplicate Source-CI matrix job");
        }
        if !expected_names.contains(name)
            || job["status"] != "completed"
            || job["conclusion"] != "success"
        {
            complete = false;
        }
    }
    complete &= names == expected_names;
    let mut stages = BTreeSet::new();
    let mut approval = None;
    let mut expiry = None;
    for handoff in handoffs {
        let stage = text(handoff, "stage")?;
        verify_handoff_metadata(handoff, &identity, stage)?;
        if !stages.insert(stage)
            || handoff["source_ref"] != request.source_ref
            || handoff["catalog_sha256"] != run["catalog_sha256"]
        {
            return Err("Source-CI handoff report binding changed");
        }
        if approval.is_some_and(|a| a != &handoff["approval_sha256"])
            || expiry.is_some_and(|e| e != &handoff["expires_epoch"])
        {
            return Err("Source-CI handoffs have different approvals");
        }
        approval = Some(&handoff["approval_sha256"]);
        expiry = Some(&handoff["expires_epoch"]);
    }
    complete &= stages == CI_STAGES.into_iter().collect();
    let (state, description) = if complete {
        ("success", "All required source CI cases passed.")
    } else if status != "completed" {
        (
            "pending",
            "Source CI is awaiting complete verified evidence.",
        )
    } else {
        (
            "failure",
            "Source CI is incomplete or a required check failed.",
        )
    };
    Ok(
        json!({"repository":SOURCE_REPOSITORY,"sha":request.identity.source_sha,"state":state,"context":CONTEXT,"description":description,
        "target_url":format!("https://github.com/{BUILDER_REPOSITORY}/actions/runs/{}/attempts/{}",request.identity.run_id,request.identity.attempt)}),
    )
}
pub fn report_cli(args: &[String], env: &Environment) -> Result<()> {
    if !args.is_empty() {
        return Err("Unexpected Source-CI reporter arguments");
    }
    require_origin(
        env,
        "source-ci-report.yml",
        &["workflow_run", "workflow_dispatch"],
    )?;
    if env.get("SOURCE_CI_REPORT_ENABLED").map(String::as_str) != Some("true") {
        return Err("Source-CI reporting is disabled");
    }
    let run_id = env
        .get("SOURCE_CI_REPORT_RUN_ID")
        .ok_or("Source-CI report run unavailable")?;
    let attempt = env
        .get("SOURCE_CI_REPORT_RUN_ATTEMPT")
        .ok_or("Source-CI report attempt unavailable")?;
    if !crate::input::positive_number(run_id, 32) || !crate::input::positive_number(attempt, 16) {
        return Err("Invalid Source-CI report run identity");
    }
    let work = tempfile::tempdir().map_err(|_| "Source-CI reporter workspace unavailable")?;
    let mut public = GitHubApi::new(env, work.path(), Role::PublicRead)?;
    let mut protected = GitHubApi::new(env, work.path(), Role::ApprovalRead)?;
    let mut source = GitHubApi::new(env, work.path(), Role::SourceRead)?;
    let current_builder =
        public.get_json(&format!("repos/{BUILDER_REPOSITORY}/git/ref/heads/main"))?;
    if current_builder["ref"] != "refs/heads/main"
        || current_builder["object"]["sha"].as_str() != env.get("GITHUB_SHA").map(String::as_str)
    {
        return Err("Source-CI reporter builder changed");
    }
    let approval = acquire_approval(
        &mut public,
        &mut protected,
        run_id,
        attempt,
        source_api::now()?,
    )?;
    public.set_deadline(approval.expires_epoch)?;
    protected.set_deadline(approval.expires_epoch)?;
    source.set_deadline(approval.expires_epoch)?;
    let request = SourceCiRequest {
        identity: approval.identity.clone(),
        source_ref: approval.source_ref.clone(),
        stage: "source".into(),
        shard_index: 0,
        shard_count: 1,
    };
    let run = subject_run(&mut public, &request.identity)?;
    let title = format!(
        "source-ci:{}:{}:{}:ci",
        request.identity.source_sha, request.identity.builder_sha, approval.catalog_sha256
    );
    if run["display_title"] != title {
        return Err("Source-CI report request title changed");
    }
    fresh_source(&mut source, &request, &approval)?;
    let jobs = run_jobs(&mut public, &request.identity)?;
    let mut normalized = Vec::new();
    for job in jobs {
        if job["status"] == "completed" && job["conclusion"] == "success" {
            hosted_job(&job)?;
        }
        normalized.push(
            json!({"name":job["name"],"status":job["status"],"conclusion":job["conclusion"]}),
        );
    }
    let mut reader = GitHubApi::new(env, work.path(), Role::HandoffRead)?;
    reader.set_deadline(approval.expires_epoch)?;
    let handoffs = read_handoffs(&mut reader, &approval)?;
    let result = source_status(
        &json!({"identity":approval.identity,"source_ref":approval.source_ref,"catalog_sha256":approval.catalog_sha256,"status":run["status"],"conclusion":run["conclusion"],"jobs":normalized}),
        &handoffs,
        &request,
    )?;
    // Recheck mutable source, current attempt, protected policy and expiry
    // immediately before the single purpose-specific status write.
    let latest = acquire_approval(
        &mut public,
        &mut protected,
        run_id,
        attempt,
        source_api::now()?,
    )?;
    if latest.digest()? != approval.digest()? {
        return Err("Source-CI report approval changed during verification");
    }
    subject_run(&mut public, &request.identity)?;
    fresh_source(&mut source, &request, &latest)?;
    let mut status = GitHubApi::new(env, work.path(), Role::Status)?;
    status.set_deadline(latest.expires_epoch)?;
    let response=status.post_json(&format!("repos/{SOURCE_REPOSITORY}/statuses/{}",request.identity.source_sha),
        &json!({"state":result["state"],"context":result["context"],"description":result["description"],"target_url":result["target_url"]}))?;
    if response["state"] != result["state"]
        || response["context"] != CONTEXT
        || response["target_url"] != result["target_url"]
    {
        return Err("Source-CI status response changed");
    }
    println!("Source-CI status reporting completed.");
    Ok(())
}
