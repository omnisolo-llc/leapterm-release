//! Full archive integration preserves the genuine native public Plan authority.
//! These hooks retain evidence; they do not qualify installers or providers.
use crate::{Environment, Result, guards, input::Request, publication_candidates};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const QUALIFICATION: &str = "retention-only-existing-native-gates-required";
fn required<'a>(env: &'a Environment, key: &str) -> Result<&'a str> {
    env.get(key)
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .ok_or("Private archive input missing")
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn command(value: &str) -> bool {
    [
        "prepare-private-final-archive",
        "verify-private-final-archive",
    ]
    .contains(&value)
}
pub fn forward(
    env: &Environment,
    request: &Request,
    target: &str,
    operation: &str,
    task: &mut Environment,
) -> Result<()> {
    if !request.build_only
        && ((["verify-build", "run"].contains(&operation)
            && crate::input::BUILD_TARGETS.contains(&target))
            || command(operation)
            || (operation == "run" && target == "publish"))
    {
        task.insert(
            "DIAGNOSTICS_PUBLIC_KEY".into(),
            required(env, "DIAGNOSTICS_PUBLIC_KEY")?.into(),
        );
    }
    if operation == "prepare-private-final-archive" || (operation == "run" && target == "publish") {
        if let Some(inputs) = env
            .get("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE")
            .filter(|s| !s.is_empty())
        {
            task.insert("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE".into(), inputs.into());
        } else if request.release_route != "option1" {
            return Err("Private archive input missing");
        }
    }
    Ok(())
}
pub fn arguments(operation: &str, env: &Environment, work: &Path) -> Result<Vec<String>> {
    if !command(operation) {
        return Err("Unsupported native archive command");
    }
    let publication = publication_candidates::directory(env)?;
    let mut args = vec![
        "helper".into(),
        "artifacts".into(),
        operation.into(),
        "--public".into(),
        publication.join("files").to_string_lossy().into_owned(),
        "--plan".into(),
        publication.join("plan.json").to_string_lossy().into_owned(),
        "--receipt".into(),
        work.join("private-final-archive.json")
            .to_string_lossy()
            .into_owned(),
        "--work".into(),
        work.to_string_lossy().into_owned(),
    ];
    if operation == "prepare-private-final-archive" {
        args.extend([
            "--input".into(),
            required(env, "INPUT_PUBLIC_CANDIDATES_DIR")?.into(),
        ]);
        let option1 = env
            .get("RELEASE_REQUEST")
            .and_then(|raw| Request::parse(raw).ok())
            .map(|req| req.release_route == "option1")
            .unwrap_or(true);
        if let Some(operator) = env
            .get("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE")
            .filter(|s| !s.is_empty())
        {
            args.extend(["--operator-inputs".into(), operator.into()]);
        } else if !option1 {
            return Err("Private archive input missing");
        }
    }
    Ok(args)
}
fn identity(env: &Environment) -> Result<crate::ci_request::PipelineIdentity> {
    crate::ci_request::PipelineIdentity::parse(&json!({
        "source_repository":required(env,"SOURCE_REPOSITORY")?,"source_sha":required(env,"RESOLVED_SOURCE_SHA")?,
        "builder_repository":required(env,"GITHUB_REPOSITORY")?,"builder_sha":required(env,"GITHUB_SHA")?,
        "run_id":required(env,"GITHUB_RUN_ID")?,"attempt":required(env,"GITHUB_RUN_ATTEMPT")?}))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    schema: u8,
    identity: crate::ci_request::PipelineIdentity,
    release: Value,
    public_plan_sha256: String,
    inventory_sha256: String,
    index_sha256: String,
    qualification: String,
}
fn proof_path(env: &Environment) -> Result<PathBuf> {
    Ok(publication_candidates::directory(env)?.join("private-archive-proof.json"))
}
struct Snapshot {
    value: Value,
    sha256: String,
}
fn snapshot(path: &Path) -> Result<Snapshot> {
    let mut file = guards::open_regular(path, 16384)?;
    guards::single_link(&file)?;
    let before = file
        .metadata()
        .map_err(|_| "Private archive proof unavailable")?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| "Private archive proof unreadable")?;
    if bytes.len() > 16384 {
        return Err("Private archive proof exceeds bound");
    }
    guards::unchanged(&file, path)?;
    if bytes.len() as u64 != before.len()
        || !guards::same(
            &before,
            &file
                .metadata()
                .map_err(|_| "Private archive proof unavailable")?,
        )
    {
        return Err("Private archive proof changed while reading");
    }
    Ok(Snapshot {
        value: crate::json::parse(&bytes)?,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}
fn require_snapshot_hash(snapshot: &Snapshot, expected: &str) -> Result<()> {
    if snapshot.sha256 != expected {
        return Err("Private archive proof differs from trusted readback output");
    }
    Ok(())
}
/// Called only after the approved native compiler/child/source freeze succeeds.
/// Re-run the actual native public Plan verifier; producer/caller JSON is never
/// substituted for package classification or genuine signing authority.
pub fn capture(env: &Environment, work: &Path, operation: &str) -> Result<String> {
    publication_candidates::verify_prepared(env)?;
    let request = publication_candidates::request(env)?;
    let identity = identity(env)?;
    let receipt = snapshot(&work.join("private-final-archive.json"))?.value;
    let fields = receipt
        .as_object()
        .ok_or("Invalid native archive receipt")?;
    let expected_key = format!(
        "final-archive/{}/{}/{}/{}/{}-{}/index.json",
        identity.builder_sha,
        identity.source_sha,
        identity.run_id,
        identity.attempt,
        request.version,
        request.build_number
    );
    if fields
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != [
            "archive_retained",
            "index_key",
            "inventory_sha256",
            "index_sha256",
            "qualification",
        ]
        .into()
        || receipt["archive_retained"] != true
        || receipt["index_key"] != expected_key
        || receipt["qualification"] != QUALIFICATION
    {
        return Err("Native archive receipt differs from approved retention");
    }
    let inventory = receipt["inventory_sha256"]
        .as_str()
        .filter(|s| hash(s))
        .ok_or("Invalid private inventory hash")?;
    let index = receipt["index_sha256"]
        .as_str()
        .filter(|s| hash(s))
        .ok_or("Invalid private index hash")?;
    let proof = Proof {
        schema: 1,
        identity,
        release: crate::json::parse(request.normalized()?.as_bytes())?,
        public_plan_sha256: required(env, "APPROVED_PUBLICATION_PLAN_SHA256")?.into(),
        inventory_sha256: inventory.into(),
        index_sha256: index.into(),
        qualification: QUALIFICATION.into(),
    };
    let raw = serde_json::to_vec(&proof).map_err(|_| "Private archive proof invalid")?;
    let path = proof_path(env)?;
    if operation == "prepare-private-final-archive" {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| "Private archive proof must be fresh")?;
        std::io::Write::write_all(&mut file, &raw)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Private archive proof write failed")?;
    } else if operation != "verify-private-final-archive" {
        return Err("Unsupported native archive command");
    }
    let held = snapshot(&path)?;
    if held.value != crate::json::parse(&raw)? {
        return Err("Independent private archive readback changed");
    }
    Ok(held.sha256)
}
/// The writer step checks a hash from the trusted source/retention/readback
/// steps, and independently invokes the unchanged native Plan verifier again.
pub fn require_publication(env: &Environment) -> Result<publication_candidates::Plan> {
    let plan = publication_candidates::verify_prepared(env)?;
    let expected = required(env, "APPROVED_PRIVATE_ARCHIVE_PROOF_SHA256")?;
    if !hash(expected) {
        return Err("Invalid private archive approval hash");
    }
    let path = proof_path(env)?;
    let held = snapshot(&path)?;
    require_snapshot_hash(&held, expected)?;
    let proof: Proof =
        serde_json::from_value(held.value).map_err(|_| "Invalid private archive proof")?;
    let request = publication_candidates::request(env)?;
    if proof.schema != 1
        || proof.identity != identity(env)?
        || proof.release != crate::json::parse(request.normalized()?.as_bytes())?
        || proof.public_plan_sha256 != required(env, "APPROVED_PUBLICATION_PLAN_SHA256")?
        || !hash(&proof.index_sha256)
        || !hash(&proof.inventory_sha256)
        || proof.qualification != QUALIFICATION
    {
        return Err("Private archive proof belongs to another request or Plan");
    }
    Ok(plan)
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn compared_proof_snapshot_keeps_its_hash_across_atomic_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("proof.json");
        // These local bytes exercise custody only; they are deliberately not
        // qualified retention or publication proof records.
        let original = br#"{"qualification":"nonqualified-local-snapshot","inventory_sha256":"first","index_sha256":"first"}"#;
        let replacement = br#"{"qualification":"nonqualified-local-snapshot","inventory_sha256":"other","index_sha256":"other"}"#;
        fs::write(&path, original).unwrap();
        let compared = snapshot(&path).unwrap();
        let staged = root.path().join("replacement.json");
        fs::write(&staged, replacement).unwrap();
        fs::rename(&staged, &path).unwrap();
        assert_eq!(compared.value, crate::json::parse(original).unwrap());
        assert_eq!(compared.sha256, format!("{:x}", Sha256::digest(original)));
        let current = snapshot(&path).unwrap();
        assert_ne!(current.sha256, compared.sha256);
        assert_eq!(
            require_snapshot_hash(&current, &compared.sha256),
            Err("Private archive proof differs from trusted readback output")
        );
        require_snapshot_hash(&compared, &compared.sha256).unwrap();
    }

    #[test]
    fn proof_snapshot_refuses_duplicate_fields_and_hardlinked_paths() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("proof.json");
        fs::write(&path, br#"{"schema":1,"schema":1}"#).unwrap();
        assert!(snapshot(&path).is_err());
        fs::write(&path, br#"{"qualification":"nonqualified-local-snapshot"}"#).unwrap();
        let second = root.path().join("second.json");
        fs::hard_link(&path, &second).unwrap();
        assert!(snapshot(&path).is_err());
        assert!(snapshot(&second).is_err());
    }
}
