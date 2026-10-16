use crate::{Environment, Result};
use serde::{Deserialize, Serialize};
pub const BUILD_TARGETS: &[&str] = &["linux", "windows", "macos", "android", "web", "ios"];
pub const RELEASE_TARGETS: &[&str] = &[
    "resolve",
    "integration",
    "installation",
    "package-signatures",
    "apple-testflight",
    "validate",
    "ios-deliver",
    "ios-submit",
    "publication-prepare",
    "vpn-container",
    "managed-rtc-provider",
    "external-tests",
    "external-windows-signing",
    "publish",
    "linux",
    "windows",
    "macos",
    "android",
    "web",
    "ios",
];
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default = "release_route")]
    pub release_route: String,
    #[serde(default)]
    pub build_only: bool,
    #[serde(default = "all")]
    pub verify_target: String,
    #[serde(default)]
    pub source_sha: String,
    #[serde(default)]
    pub builder_sha: String,
    #[serde(default = "version")]
    pub version: String,
    pub build_number: String,
    #[serde(default = "skip")]
    pub ios_action: String,
    #[serde(default)]
    pub automatic_release: bool,
    #[serde(default = "yes")]
    pub include_selfhost: bool,
    #[serde(default)]
    pub preview_windows_self_sign: bool,
    #[serde(default)]
    pub auto_promote: bool,
}
fn yes() -> bool {
    true
}
fn release_route() -> String {
    "option1".into()
}
fn all() -> String {
    "all".into()
}
fn version() -> String {
    "0.1.0".into()
}
fn skip() -> String {
    "skip".into()
}
pub fn validate_approval(env: &Environment, source: &str, builder: &str) -> Result<()> {
    if !valid_sha(&source.to_ascii_lowercase())
        || !valid_sha(builder)
        || env.get("APPROVED_RELEASE_SOURCE_SHA") != Some(&source.to_ascii_lowercase())
        || env.get("APPROVED_RELEASE_BUILDER_SHA").map(String::as_str) != Some(builder)
        || env.get("GITHUB_SHA").map(String::as_str) != Some(builder)
    {
        return Err("Protected source and builder approval differs from this run");
    }
    Ok(())
}
pub fn valid_sha(sha: &str) -> bool {
    sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && !sha.bytes().all(|b| b == b'0')
}
pub fn positive_number(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit())
}
pub fn valid_repo_slug(value: &str) -> bool {
    let Some((owner, repo)) = value.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !repo.is_empty()
        && !repo.contains('/')
        && value != "omnisolo-llc/leapterm-release"
        && [owner, repo].into_iter().all(|part| {
            part.len() <= 100
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}
impl Request {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > 16384 {
            return Err("Release request exceeds its bound");
        }
        let mut request: Self = serde_json::from_str(raw)
            .map_err(|_| "Invalid, duplicate or unknown release fields")?;
        request.source_sha = request.source_sha.to_ascii_lowercase();
        if request.version.is_empty() {
            request.version = version();
        }
        if !["option1", "legacy-acceptance"].contains(&request.release_route.as_str())
            || (request.release_route == "legacy-acceptance" && request.build_only)
            || (!BUILD_TARGETS.contains(&request.verify_target.as_str())
                && request.verify_target != "all")
            || (request.build_only && request.ios_action != "skip")
            || (!request.build_only
                && (request.verify_target != "all"
                    || !matches!(request.ios_action.as_str(), "upload" | "submit")
                    || !request.include_selfhost))
            || (request.automatic_release && (request.build_only || request.ios_action != "submit"))
            || (request.preview_windows_self_sign
                && (!request.build_only || request.verify_target != "windows"))
        {
            return Err("Invalid release mode or distribution selection");
        }
        if (!request.source_sha.is_empty() && !valid_sha(&request.source_sha))
            || (!request.builder_sha.is_empty() && !valid_sha(&request.builder_sha))
        {
            return Err("Invalid release revision");
        }
        let version: Vec<_> = request.version.split('.').collect();
        if version.len() != 3
            || version.iter().any(|v| {
                v.is_empty()
                    || v.len() > 4
                    || !v.bytes().all(|b| b.is_ascii_digit())
                    || (v.len() > 1 && v.starts_with('0'))
            })
            || !positive_number(&request.build_number, 4)
        {
            return Err("Invalid release version or build number");
        }
        Ok(request)
    }
    pub fn validate_target(&self, target: &str) -> Result<()> {
        if !RELEASE_TARGETS.contains(&target)
            || (self.build_only && target != "resolve" && !BUILD_TARGETS.contains(&target))
            || (self.build_only
                && BUILD_TARGETS.contains(&target)
                && self.verify_target != "all"
                && self.verify_target != target)
            || (target == "ios-submit" && self.ios_action != "submit")
        {
            return Err("Release target differs from authorized request mode");
        }
        Ok(())
    }
    pub fn normalized(&self) -> Result<String> {
        let mut value = serde_json::to_value(self).map_err(|_| "Invalid release request")?;
        let object = value.as_object_mut().ok_or("Invalid release request")?;
        object.remove("verify_target");
        object.remove("builder_sha");
        object.remove("preview_windows_self_sign");
        object.remove("auto_promote");
        serde_json::to_string(&value).map_err(|_| "Invalid release request")
    }
    pub fn resolve_from(&mut self, env: &Environment) -> Result<()> {
        for (key, expected) in [
            ("RESOLVED_VERSION", &self.version),
            ("RESOLVED_BUILD_NUMBER", &self.build_number),
        ] {
            if env.get(key).is_some_and(|v| !v.is_empty() && v != expected) {
                return Err("Resolved release inputs differ from request");
            }
        }
        if let Some(sha) = env.get("RESOLVED_SOURCE_SHA").filter(|v| !v.is_empty()) {
            if !valid_sha(sha) || (!self.source_sha.is_empty() && self.source_sha != *sha) {
                return Err("Resolved source differs from request");
            }
            self.source_sha = sha.clone();
        }
        Ok(())
    }
}
pub fn validate_request(raw: &str) -> Result<()> {
    Request::parse(raw).map(|_| ())
}
pub fn validate_authority(env: &Environment) -> Result<()> {
    if env.contains_key("SOURCE_ENTRYPOINT") {
        return Err("Legacy source entrypoint input is unsupported");
    }
    for (name, expected) in [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REPOSITORY", "omnisolo-llc/leapterm-release"),
        ("GITHUB_REF", "refs/heads/main"),
        (
            "GITHUB_WORKFLOW_REF",
            "omnisolo-llc/leapterm-release/.github/workflows/release.yml@refs/heads/main",
        ),
        ("SOURCE_BRANCH", "main"),
    ] {
        if env.get(name).map(String::as_str) != Some(expected) {
            return Err("Untrusted native release authority");
        }
    }
    if !env
        .get("SOURCE_REPOSITORY")
        .is_some_and(|v| valid_repo_slug(v))
    {
        return Err("Untrusted native release authority");
    }
    if !env.get("GITHUB_SHA").is_some_and(|v| valid_sha(v))
        || !["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]
            .iter()
            .all(|k| env.get(*k).is_some_and(|v| positive_number(v, 24)))
    {
        return Err("Invalid native workflow identity");
    }
    Ok(())
}
