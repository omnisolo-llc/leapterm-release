#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const PUBLIC_RELEASE_REPO = 'omnisolo-llc/leapterm-release';
export const BASELINE_VERSION = '0.1.4';
export const BASELINE_BUILD_NUMBER = 71;
export const MAX_ACTIVE_RUN_AGE_MS = 6 * 60 * 60 * 1000;
export const ALLOWED_VERIFY_TARGETS = Object.freeze([
  'all',
  'fast',
  'slow',
  'linux',
  'windows',
  'macos',
  'android',
  'web',
  'ios',
]);

function trimEnv(env, key) {
  return String(env?.[key] ?? '').trim();
}

function parseBoolEnv(env, key, defaultValue = true) {
  const raw = trimEnv(env, key).toLowerCase();
  if (!raw) return defaultValue;
  if (raw === 'true' || raw === '1' || raw === 'yes') return true;
  if (raw === 'false' || raw === '0' || raw === 'no') return false;
  throw new Error(`Invalid boolean input for ${key}: "${raw}"`);
}

export function parseSemverTag(rawTag) {
  if (!rawTag || typeof rawTag !== 'string') return null;
  const trimmed = rawTag.trim().replace(/^refs\/tags\//, '');
  if (!trimmed || trimmed.startsWith('ci-stage/')) return null;
  const match = trimmed.match(
    /^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?:-(?:fast|slow|(?:b|build)?(\d{1,4})))?$/i,
  );
  if (!match) return null;
  const parts = [Number(match[1]), Number(match[2]), Number(match[3])];
  if (parts.some((n) => !Number.isSafeInteger(n) || n < 0)) return null;
  const buildNumber = match[4] ? Number(match[4]) : null;
  return {
    version: `${parts[0]}.${parts[1]}.${parts[2]}`,
    parts,
    buildNumber:
      buildNumber && Number.isSafeInteger(buildNumber) && buildNumber > 0
        ? buildNumber
        : null,
  };
}

export function compareSemver(a, b) {
  const pa = parseSemverTag(a);
  const pb = parseSemverTag(b);
  if (!pa && !pb) return 0;
  if (!pa) return -1;
  if (!pb) return 1;
  for (let i = 0; i < 3; i += 1) {
    if (pa.parts[i] !== pb.parts[i]) return pa.parts[i] - pb.parts[i];
  }
  return 0;
}

export function selectVerificationVersion(versions = [], baseline = BASELINE_VERSION) {
  let highest = baseline;
  for (const candidate of versions) {
    const parsed = parseSemverTag(candidate);
    if (parsed && compareSemver(parsed.version, highest) > 0) {
      highest = parsed.version;
    }
  }
  return (parseSemverTag(highest) || parseSemverTag(BASELINE_VERSION)).version;
}

/**
 * Matches `ci/native-release/src/source_discovery.rs::correlation_id` exactly:
 * first 24 lowercase hex characters of SHA-256("leap-source-ci-v1:<repo>:<sourceSha>:<builderSha>:<stage>").
 */
export function computeSourceCiCorrelationId(
  sourceRepository,
  sourceSha,
  builderSha,
  stage = 'ci',
) {
  if (!sourceRepository || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(sourceRepository)) {
    throw new Error('Invalid source repository slug for correlation ID');
  }
  if (!/^[0-9a-f]{40}$/i.test(sourceSha || '')) {
    throw new Error(`Invalid 40-hex source_sha "${sourceSha}"`);
  }
  if (!/^[0-9a-f]{40}$/i.test(builderSha || '')) {
    throw new Error(`Invalid 40-hex builder_sha "${builderSha}"`);
  }
  const payload = `leap-source-ci-v1:${sourceRepository}:${sourceSha.toLowerCase()}:${builderSha.toLowerCase()}:${stage}`;
  return createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 24);
}

function githubHeaders(token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'leapterm-nightly-qa-dispatcher',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

function isRecentActiveRun(run, nowMs = Date.now()) {
  if (!run || (run.status !== 'in_progress' && run.status !== 'queued')) {
    return false;
  }
  const createdMs = run.created_at ? Date.parse(String(run.created_at)) : Number.NaN;
  if (Number.isFinite(createdMs) && nowMs - createdMs > MAX_ACTIVE_RUN_AGE_MS) {
    return false;
  }
  return true;
}

export async function collectPublicQaWorkflowState({
  publicRepo = PUBLIC_RELEASE_REPO,
  token = '',
  fetchImpl = fetch,
} = {}) {
  const headers = githubHeaders(token);
  const versions = new Set();
  let maxBuildNumber = BASELINE_BUILD_NUMBER;
  let builderHeadSha = '';
  const activeReleaseVerifyRunIds = [];
  const activeSourceCiRunIds = [];

  try {
    const refRes = await fetchImpl(
      `https://api.github.com/repos/${publicRepo}/git/ref/heads/main`,
      { headers },
    );
    if (refRes.ok) {
      const refJson = await refRes.json();
      const sha = String(refJson?.object?.sha || '').trim().toLowerCase();
      if (/^[0-9a-f]{40}$/.test(sha)) {
        builderHeadSha = sha;
      }
    }
  } catch {
    // Best-effort builder ref lookup.
  }

  try {
    const relRes = await fetchImpl(
      `https://api.github.com/repos/${publicRepo}/releases?per_page=50`,
      { headers },
    );
    if (relRes.ok) {
      const releases = await relRes.json();
      if (Array.isArray(releases)) {
        for (const rel of releases) {
          const parsed = parseSemverTag(String(rel?.tag_name || ''));
          if (!parsed) continue;
          versions.add(parsed.version);
          if (parsed.buildNumber && parsed.buildNumber > maxBuildNumber) {
            maxBuildNumber = parsed.buildNumber;
          }
        }
      }
    }
  } catch {
    // Best-effort release tag discovery.
  }

  try {
    const relRunsRes = await fetchImpl(
      `https://api.github.com/repos/${publicRepo}/actions/workflows/release.yml/runs?per_page=10`,
      { headers },
    );
    if (relRunsRes.ok) {
      const runsJson = await relRunsRes.json();
      const runs = Array.isArray(runsJson?.workflow_runs) ? runsJson.workflow_runs : [];
      for (const run of runs) {
        if (isRecentActiveRun(run)) {
          activeReleaseVerifyRunIds.push(run.id);
        }
      }
    }
  } catch {
    // Best-effort active release.yml inspection.
  }

  for (const wf of ['source-ci.yml', 'source-discovery.yml']) {
    try {
      const wfRes = await fetchImpl(
        `https://api.github.com/repos/${publicRepo}/actions/workflows/${wf}/runs?per_page=10`,
        { headers },
      );
      if (wfRes.ok) {
        const wfJson = await wfRes.json();
        const runs = Array.isArray(wfJson?.workflow_runs) ? wfJson.workflow_runs : [];
        for (const run of runs) {
          if (isRecentActiveRun(run)) {
            activeSourceCiRunIds.push(run.id);
          }
        }
      }
    } catch {
      // Best-effort active source-ci inspection.
    }
  }

  return {
    versions: [...versions],
    maxBuildNumber,
    builderHeadSha,
    activeReleaseVerifyRunIds,
    activeSourceCiRunIds,
  };
}

export function buildSourceCiDispatchArgs({
  publicRepo = PUBLIC_RELEASE_REPO,
  sourceSha,
  sourceRef = 'refs/heads/main',
  builderSha,
  catalogSha256,
  correlationId,
} = {}) {
  if (!/^[0-9a-f]{40}$/i.test(sourceSha || '')) {
    throw new Error(`Invalid source_sha "${sourceSha}" (expected 40-hex commit SHA)`);
  }
  if (!/^[0-9a-f]{40}$/i.test(builderSha || '')) {
    throw new Error(`Invalid builder_sha "${builderSha}" (expected 40-hex commit SHA)`);
  }
  if (!/^[0-9a-f]{64}$/i.test(catalogSha256 || '')) {
    throw new Error(`Invalid catalog_sha256 "${catalogSha256}" (expected 64-hex SHA-256)`);
  }
  if (!/^[0-9a-f]{24}$/.test(correlationId || '')) {
    throw new Error(`Invalid correlation_id "${correlationId}" (expected 24 lowercase hex chars)`);
  }
  if (!sourceRef || !/^refs\/(?:heads\/main|pull\/\d+\/head)$/.test(sourceRef)) {
    throw new Error(`Invalid source_ref "${sourceRef}"`);
  }
  return [
    'workflow',
    'run',
    'source-ci.yml',
    '-R',
    publicRepo,
    '--ref',
    'main',
    '-f',
    `source_sha=${sourceSha.toLowerCase()}`,
    '-f',
    `source_ref=${sourceRef}`,
    '-f',
    `builder_sha=${builderSha.toLowerCase()}`,
    '-f',
    `catalog_sha256=${catalogSha256.toLowerCase()}`,
    '-f',
    `correlation_id=${correlationId}`,
  ];
}

export function buildSourceDiscoveryDispatchArgs({
  publicRepo = PUBLIC_RELEASE_REPO,
} = {}) {
  return [
    'workflow',
    'run',
    'source-discovery.yml',
    '-R',
    publicRepo,
    '--ref',
    'main',
  ];
}

export function buildBuildOnlyReleaseDispatchArgs({
  publicRepo = PUBLIC_RELEASE_REPO,
  verifyTarget = 'all',
  version = BASELINE_VERSION,
  buildNumber = 1,
  sourceSha = '',
  runTest = true,
} = {}) {
  const normalizedTarget = String(verifyTarget || 'all').trim().toLowerCase();
  if (!ALLOWED_VERIFY_TARGETS.includes(normalizedTarget)) {
    throw new Error(
      `Unsupported verify_target "${verifyTarget}"; expected one of: ${ALLOWED_VERIFY_TARGETS.join(', ')}`,
    );
  }
  const parsedVersion = parseSemverTag(String(version || ''));
  if (!parsedVersion) {
    throw new Error(`Invalid semver version "${version}"`);
  }
  const normalizedBuild = String(buildNumber ?? '').trim();
  if (!/^[1-9]\d{0,3}$/.test(normalizedBuild)) {
    throw new Error(`Invalid build_number "${buildNumber}" (expected 1-9999)`);
  }

  const args = [
    'workflow',
    'run',
    'release.yml',
    '-R',
    publicRepo,
    '--ref',
    'main',
    '-f',
    'release_route=option1',
    '-f',
    'build_only=true',
    '-f',
    `verify_target=${normalizedTarget}`,
    '-f',
    `version=${parsedVersion.version}`,
    '-f',
    `build_number=${normalizedBuild}`,
    '-f',
    'ios_action=skip',
    '-f',
    'automatic_release=false',
    '-f',
    'include_selfhost=false',
    '-f',
    'auto_promote=false',
    '-f',
    `run_test=${runTest ? 'true' : 'false'}`,
  ];

  if (sourceSha) {
    if (!/^[0-9a-f]{40}$/i.test(sourceSha)) {
      throw new Error(`Invalid explicit source_sha "${sourceSha}"`);
    }
    args.push('-f', `source_sha=${sourceSha.toLowerCase()}`);
  }
  return args;
}

export async function resolveNightlyQaPlan({
  env = process.env,
  fetchImpl = fetch,
} = {}) {
  const publicRepo = trimEnv(env, 'PUBLIC_RELEASE_REPO') || PUBLIC_RELEASE_REPO;
  const sourceRepo = trimEnv(env, 'SOURCE_REPOSITORY');
  const verifyTarget = (
    trimEnv(env, 'INPUT_VERIFY_TARGET') ||
    trimEnv(env, 'VERIFY_TARGET') ||
    'all'
  ).toLowerCase();
  if (!ALLOWED_VERIFY_TARGETS.includes(verifyTarget)) {
    throw new Error(
      `Unsupported verify_target "${verifyTarget}"; expected one of: ${ALLOWED_VERIFY_TARGETS.join(', ')}`,
    );
  }

  const dispatchSourceCi = parseBoolEnv(env, 'INPUT_DISPATCH_SOURCE_CI', true);
  const dispatchBuildVerify = parseBoolEnv(env, 'INPUT_DISPATCH_BUILD_VERIFY', true);
  const runTest = parseBoolEnv(env, 'INPUT_RUN_TEST', true);
  const explicitSourceSha = trimEnv(env, 'INPUT_SOURCE_SHA');
  const explicitCatalogSha256 = trimEnv(env, 'INPUT_CATALOG_SHA256');
  const discoveryEnabled = trimEnv(env, 'SOURCE_CI_DISCOVERY_ENABLED') === 'true';

  if (explicitSourceSha && !/^[0-9a-f]{40}$/i.test(explicitSourceSha)) {
    throw new Error(`Invalid explicit source_sha "${explicitSourceSha}" (expected 40-hex SHA)`);
  }
  if (explicitCatalogSha256 && !/^[0-9a-f]{64}$/i.test(explicitCatalogSha256)) {
    throw new Error(
      `Invalid explicit catalog_sha256 "${explicitCatalogSha256}" (expected 64-hex SHA-256)`,
    );
  }

  const token =
    trimEnv(env, 'GH_TOKEN') ||
    trimEnv(env, 'PRIVATE_RELEASE_TOKEN') ||
    trimEnv(env, 'GITHUB_TOKEN');

  const state = await collectPublicQaWorkflowState({
    publicRepo,
    token,
    fetchImpl,
  });

  const builderSha =
    (/^[0-9a-f]{40}$/i.test(trimEnv(env, 'GITHUB_SHA'))
      ? trimEnv(env, 'GITHUB_SHA').toLowerCase()
      : '') || state.builderHeadSha;

  const version = selectVerificationVersion(state.versions, BASELINE_VERSION);
  const buildNumber = Math.min(9999, Math.max(1, state.maxBuildNumber));

  let sourceCiMode = 'disabled';
  let sourceCiArgs = null;
  if (dispatchSourceCi) {
    if (explicitSourceSha && explicitCatalogSha256 && sourceRepo && builderSha) {
      const correlationId = computeSourceCiCorrelationId(
        sourceRepo,
        explicitSourceSha,
        builderSha,
        'ci',
      );
      sourceCiMode = 'direct';
      sourceCiArgs = buildSourceCiDispatchArgs({
        publicRepo,
        sourceSha: explicitSourceSha,
        sourceRef: 'refs/heads/main',
        builderSha,
        catalogSha256: explicitCatalogSha256,
        correlationId,
      });
    } else if (discoveryEnabled) {
      sourceCiMode = 'discovery';
      sourceCiArgs = buildSourceDiscoveryDispatchArgs({ publicRepo });
    } else {
      sourceCiMode = 'unconfigured';
    }
  }

  const buildVerifyArgs = dispatchBuildVerify
    ? buildBuildOnlyReleaseDispatchArgs({
        publicRepo,
        verifyTarget,
        version,
        buildNumber,
        sourceSha: explicitSourceSha,
        runTest,
      })
    : null;

  return {
    publicRepo,
    verifyTarget,
    version,
    buildNumber,
    sourceSha: explicitSourceSha ? explicitSourceSha.toLowerCase() : '',
    builderSha,
    dispatchSourceCi,
    sourceCiMode,
    sourceCiArgs,
    dispatchBuildVerify,
    buildVerifyArgs,
    runTest,
    activeReleaseVerifyRunIds: state.activeReleaseVerifyRunIds,
    activeSourceCiRunIds: state.activeSourceCiRunIds,
  };
}

export async function main({
  env = process.env,
  fetchImpl = fetch,
  execFileImpl = execFileSync,
} = {}) {
  const plan = await resolveNightlyQaPlan({ env, fetchImpl });
  const isScheduled =
    trimEnv(env, 'GITHUB_EVENT_NAME') === 'schedule' &&
    trimEnv(env, 'FORCE_DISPATCH') !== 'true';
  const dryRun = env.DRY_RUN === 'true' || process.argv.includes('--dry-run');

  const dispatched = {
    sourceCi: false,
    buildVerify: false,
    skippedSourceCi: false,
    skippedBuildVerify: false,
  };

  if (plan.dispatchSourceCi) {
    if (isScheduled && plan.activeSourceCiRunIds.length > 0) {
      console.log(
        `[nightly-qa] Active source-ci/discovery run(s) already in progress (${plan.activeSourceCiRunIds.join(', ')}); skipping duplicate scheduled Source-CI dispatch.`,
      );
      dispatched.skippedSourceCi = true;
    } else if (plan.sourceCiArgs) {
      console.log(`[nightly-qa] Source-CI mode=${plan.sourceCiMode}: gh ${plan.sourceCiArgs.join(' ')}`);
      if (!dryRun) {
        execFileImpl('gh', plan.sourceCiArgs, { stdio: 'inherit', env });
      }
      dispatched.sourceCi = true;
    } else {
      console.log(
        '[nightly-qa] Source-CI discovery is not enabled and explicit catalog_sha256 was not provided; skipping Source-CI dispatch.',
      );
      dispatched.skippedSourceCi = true;
    }
  }

  if (plan.dispatchBuildVerify && plan.buildVerifyArgs) {
    if (isScheduled && plan.activeReleaseVerifyRunIds.length > 0) {
      console.log(
        `[nightly-qa] Active release.yml run(s) already in progress (${plan.activeReleaseVerifyRunIds.join(', ')}); skipping duplicate scheduled build_only verification dispatch.`,
      );
      dispatched.skippedBuildVerify = true;
    } else {
      console.log(
        `[nightly-qa] Build-only multi-platform verify (${plan.verifyTarget}): gh ${plan.buildVerifyArgs.join(' ')}`,
      );
      if (!dryRun) {
        execFileImpl('gh', plan.buildVerifyArgs, { stdio: 'inherit', env });
      }
      dispatched.buildVerify = true;
    }
  }

  return { ...plan, dispatched, dryRun };
}

const isDirectRun =
  Boolean(process.argv[1]) &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isDirectRun) {
  main().catch((err) => {
    console.error(
      '[nightly-qa] Fatal:',
      err instanceof Error ? err.message : String(err),
    );
    process.exit(1);
  });
}
