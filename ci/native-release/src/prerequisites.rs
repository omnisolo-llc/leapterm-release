//! Presence-only preflight. The workflow passes booleans, never credentials.
//! This is not a test receipt and cannot certify devices, signatures or packages.
use crate::{Environment, Result};

const NAMES: [&str; 8] = [
    "SOURCE_REPOSITORY",
    "SOURCE_BRANCH",
    "SOURCE_DEPLOY_KEY",
    "SOURCE_KNOWN_HOSTS",
    "BUILD_CONFIG",
    "STORAGE_CONFIG",
    "OMNITERM_VPN_PROVIDER_PUBLIC_KEY",
    "OMNI_INTEGRATION_DEVICE",
];

pub fn check_integration(env: &Environment) -> Result<()> {
    let raw = env
        .get("RELEASE_PREREQUISITE_PRESENCE")
        .ok_or("Integration prerequisite presence metadata is missing")?;
    if raw.len() > 8192 {
        return Err("Invalid integration prerequisite presence metadata");
    }
    let value = crate::json::parse(raw.as_bytes())
        .map_err(|_| "Invalid integration prerequisite presence metadata")?;
    let flags = value
        .as_object()
        .ok_or("Invalid integration prerequisite presence metadata")?;
    if flags.len() != NAMES.len()
        || NAMES
            .iter()
            .any(|name| !flags.get(*name).is_some_and(serde_json::Value::is_boolean))
    {
        return Err("Invalid integration prerequisite presence metadata");
    }
    let mut incomplete = false;
    for name in NAMES {
        if flags[name] == false {
            eprintln!("Missing integration prerequisite: {name}");
            incomplete = true;
        }
    }
    if incomplete {
        return Err("Integration prerequisites are incomplete; no private source was executed");
    }
    println!(
        "Integration configuration names are present; values, devices and execution evidence remain unverified."
    );
    Ok(())
}
