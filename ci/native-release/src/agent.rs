use crate::{
    Environment, Result, guards,
    input::{Request, positive_number, valid_sha},
    json,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, io::Read, path::Path};
pub const PLATFORMS: &[&str] = &[
    "linux-x86_64",
    "linux-aarch64",
    "darwin-x86_64",
    "darwin-aarch64",
    "windows-x86_64",
    "windows-aarch64",
];
pub const WORKFLOW_REF: &str =
    "omnisolo-llc/omniterm-release/.github/workflows/omni-agent.yml@refs/heads/main";
const MAX_BYTES: u64 = 512 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub source_sha: String,
    pub source_branch: String,
    pub version: String,
}
pub fn approved_source() -> Result<Pin> {
    read_pin(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("Agent pin missing")?
            .join("approved_agent_source.json"),
    )
}
pub fn read_pin(path: &Path) -> Result<Pin> {
    let file = guards::open_regular(path, 4096)?;
    let pin: Pin = serde_json::from_reader(file).map_err(|_| "Invalid pinned agent fields")?;
    if !valid_sha(&pin.source_sha)
        || !pin.source_branch.starts_with("release/omni-agent-")
        || pin.source_branch.len() <= "release/omni-agent-".len()
        || pin.source_branch.contains("..")
        || !pin.source_branch["release/omni-agent-".len()..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err("Invalid pinned agent identity");
    }
    package_names(&pin.version, PLATFORMS[0])?;
    Ok(pin)
}
pub fn target(platform: &str) -> Result<&'static str> {
    if !PLATFORMS.contains(&platform) {
        return Err("Invalid agent platform");
    }
    Ok(if platform.starts_with("darwin-") {
        "macos"
    } else if platform.starts_with("windows-") {
        "windows"
    } else {
        "linux"
    })
}
pub fn validate_authority(env: &Environment) -> Result<()> {
    let pin = approved_source()?;
    for (key, value) in [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REPOSITORY", "omnisolo-llc/omniterm-release"),
        ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_WORKFLOW_REF", WORKFLOW_REF),
        ("SOURCE_REPOSITORY", "omnisolo-llc/omniterm"),
        ("SOURCE_BRANCH", pin.source_branch.as_str()),
        ("RESOLVED_SOURCE_SHA", pin.source_sha.as_str()),
    ] {
        if env.get(key).map(String::as_str) != Some(value) {
            return Err("Untrusted pinned agent authority");
        }
    }
    if env.contains_key("SOURCE_ENTRYPOINT") {
        return Err("Legacy source entrypoint input is unsupported");
    }
    if !env.get("GITHUB_SHA").is_some_and(|s| valid_sha(s))
        || !["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]
            .iter()
            .all(|key| env.get(*key).is_some_and(|s| positive_number(s, 24)))
    {
        return Err("Invalid agent workflow identity");
    }
    let platform = env
        .get("OMNI_AGENT_PLATFORM")
        .ok_or("Agent platform missing")?;
    if env.get("RELEASE_TARGET").map(String::as_str) != Some(target(platform)?) {
        return Err("Agent target mismatch");
    }
    let raw = env.get("RELEASE_REQUEST").ok_or("Agent request missing")?;
    let request = Request::parse(raw)?;
    let value = json::parse(raw.as_bytes())?;
    let expected = serde_json::json!({"source_sha":pin.source_sha,"version":pin.version,"build_number":"1","ios_action":"skip","build_only":true,"automatic_release":false,"include_selfhost":true});
    if value != expected || request.preview_windows_self_sign {
        return Err("Agent request must be pinned and cannot publish");
    }
    Ok(())
}
pub fn package_names(version: &str, platform: &str) -> Result<BTreeSet<String>> {
    target(platform)?;
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3
        || parts.iter().zip([255, 255, 65535]).any(|(s, max)| {
            s.is_empty()
                || (s.len() > 1 && s.starts_with('0'))
                || !s.bytes().all(|b| b.is_ascii_digit())
                || !s.parse::<u32>().is_ok_and(|n| n <= max)
        })
    {
        return Err("Invalid package version or MSI bounds");
    }
    let stem = format!("omniterm-agent-v{version}-{platform}");
    let mut names = BTreeSet::from([
        format!(
            "omniterm-agent-{platform}{}",
            if platform.starts_with("windows-") {
                ".exe"
            } else {
                ""
            }
        ),
        format!("{stem}.zip"),
    ]);
    if platform.starts_with("windows-") {
        names.extend([format!("{stem}.msi"), format!("{stem}-setup.exe")]);
    } else if platform.starts_with("darwin-") {
        names.extend([
            format!("{stem}.tar.gz"),
            format!("{stem}.pkg"),
            format!("{stem}.dmg"),
        ]);
    } else {
        let (deb, rpm) = if platform.ends_with("x86_64") {
            ("amd64", "x86_64")
        } else {
            ("arm64", "aarch64")
        };
        names.extend([
            format!("{stem}.tar.gz"),
            format!("omniterm-agent_{version}_{deb}.deb"),
            format!("omniterm-agent-{version}-1.{rpm}.rpm"),
        ]);
    }
    Ok(names)
}
pub fn payload_names(platform: &str) -> BTreeSet<&'static str> {
    let mut names = BTreeSet::from(["README.txt", "LICENSE.txt"]);
    if platform.starts_with("windows-") {
        names.insert("omniterm-agent.exe");
    } else {
        names.extend(["omniterm-agent", "omniterm-task-runner"]);
    }
    names
}
fn fields(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|o| {
        o.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected.iter().copied().collect()
    })
}
fn record(value: &Value, asset: bool) -> bool {
    fields(
        value,
        if asset {
            &["name", "size", "sha256"]
        } else {
            &["size", "sha256"]
        },
    ) && value["size"]
        .as_u64()
        .is_some_and(|n| n > 0 && n <= MAX_BYTES)
        && value["sha256"].as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn inventory(root: &Path) -> Result<BTreeSet<String>> {
    fs::read_dir(root)
        .map_err(|_| "Handoff directory unavailable")?
        .map(|e| {
            e.map_err(|_| "Handoff inventory unavailable")
                .and_then(|e| {
                    e.file_name()
                        .into_string()
                        .map_err(|_| "Invalid handoff filename")
                })
        })
        .collect()
}
pub fn verify_handoff(root: &Path, version: &str, platform: &str) -> Result<usize> {
    guards::directory(root)?;
    let names = package_names(version, platform)?;
    let manifest = format!("packages-{platform}.json");
    let mut expected = names.clone();
    expected.insert(manifest.clone());
    if inventory(root)? != expected {
        return Err("Incomplete or unexpected handoff files");
    }
    let mut bytes = Vec::new();
    guards::open_regular(&root.join(manifest), 65536)?
        .read_to_end(&mut bytes)
        .map_err(|_| "Handoff manifest unavailable")?;
    let value = json::parse(&bytes)?;
    if !fields(
        &value,
        &[
            "schema",
            "version",
            "platform",
            "platform_signing",
            "payload",
            "assets",
        ],
    ) || value["schema"].as_u64() != Some(1)
        || value["version"] != version
        || value["platform"] != platform
        || value["platform_signing"] != "not_performed"
    {
        return Err("Handoff identity or signing status mismatch");
    }
    let payload = value["payload"]
        .as_object()
        .ok_or("Invalid payload metadata")?;
    if payload.keys().map(String::as_str).collect::<BTreeSet<_>>() != payload_names(platform)
        || !payload.values().all(|v| record(v, false))
    {
        return Err("Unexpected payload metadata");
    }
    let assets = value["assets"].as_array().ok_or("Invalid handoff assets")?;
    if assets.len() != names.len()
        || !assets.iter().all(|v| record(v, true))
        || assets
            .iter()
            .filter_map(|v| v["name"].as_str())
            .map(String::from)
            .collect::<BTreeSet<_>>()
            != names
    {
        return Err("Handoff assets do not cover exact inventory");
    }
    for asset in assets {
        let path = root.join(asset["name"].as_str().ok_or("Invalid asset name")?);
        let mut file = guards::open_regular(&path, MAX_BYTES)?;
        let before = file.metadata().map_err(|_| "Asset unavailable")?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buffer).map_err(|_| "Asset unreadable")?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_BYTES {
                return Err("Asset exceeds bound");
            }
            digest.update(&buffer[..n]);
        }
        guards::unchanged(&file, &path)?;
        let after = fs::symlink_metadata(&path).map_err(|_| "Asset changed")?;
        if total != asset["size"].as_u64().ok_or("Invalid asset size")?
            || format!("{:x}", digest.finalize()) != asset["sha256"]
            || !guards::same(&before, &after)
        {
            return Err("Asset bytes differ from manifest or changed during verification");
        }
    }
    if inventory(root)? != expected {
        return Err("Handoff inventory changed");
    }
    Ok(names.len())
}
