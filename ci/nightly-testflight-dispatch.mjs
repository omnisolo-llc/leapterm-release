#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createPrivateKey, sign } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const PUBLIC_RELEASE_REPO = 'omnisolo-llc/leapterm-release';
export const DEFAULT_ASC_APP_ID = '6812974189';
export const BASELINE_VERSION = '0.1.3';
export const BASELINE_BUILD_NUMBER = 71;
export const ALLOWED_SCHEDULED_TARGETS = Object.freeze(['all', 'slow', 'fast']);

function trimEnv(env, key) {
  return String(env?.[key] ?? '').trim();
}

export function parseSemverTag(rawTag) {
  if (!rawTag || typeof rawTag !== 'string') {
    return null;
  }
  const trimmed = rawTag.trim().replace(/^refs\/tags\//, '');
  if (!trimmed || trimmed.startsWith('ci-stage/')) {
    return null;
  }
  const match = trimmed.match(
    /^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?:-(?:fast|slow|(?:b|build)?(\d{1,4})))?$/i,
  );
  if (!match) {
    return null;
  }
  const parts = [Number(match[1]), Number(match[2]), Number(match[3])];
  if (parts.some((n) => !Number.isSafeInteger(n) || n < 0)) {
    return null;
  }
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
    if (pa.parts[i] !== pb.parts[i]) {
      return pa.parts[i] - pb.parts[i];
    }
  }
  return 0;
}

export function computeNextPatchVersion(versions = [], baseline = BASELINE_VERSION) {
  let highest = baseline;
  for (const candidate of versions) {
    if (parseSemverTag(candidate) && compareSemver(candidate, highest) > 0) {
      highest = parseSemverTag(candidate).version;
    }
  }
  const parsed = parseSemverTag(highest) || parseSemverTag(BASELINE_VERSION);
  return `${parsed.parts[0]}.${parsed.parts[1]}.${parsed.parts[2] + 1}`;
}

export function resolveAppleApiCredentials(env = process.env) {
  let jsonConfig = {};
  const rawJson = trimEnv(env, 'APPLE_CONFIG') || trimEnv(env, 'IOS_SIGNING_CONFIG');
  if (rawJson) {
    try {
      const parsed = JSON.parse(rawJson);
      if (parsed && typeof parsed === 'object') {
        jsonConfig = parsed;
      }
    } catch {
      // Ignore malformed optional fallback JSON; direct env vars take precedence.
    }
  }
  const keyId =
    trimEnv(env, 'APP_STORE_CONNECT_KEY_ID') ||
    String(jsonConfig.APP_STORE_CONNECT_KEY_ID || '').trim();
  const issuerId =
    trimEnv(env, 'APP_STORE_CONNECT_ISSUER_ID') ||
    String(jsonConfig.APP_STORE_CONNECT_ISSUER_ID || '').trim();
  const apiKeyBase64 =
    trimEnv(env, 'APP_STORE_CONNECT_API_KEY_BASE64') ||
    String(jsonConfig.APP_STORE_CONNECT_API_KEY_BASE64 || '').trim();
  const appId =
    trimEnv(env, 'APP_STORE_CONNECT_APP_ID') ||
    String(jsonConfig.APP_STORE_CONNECT_APP_ID || '').trim() ||
    DEFAULT_ASC_APP_ID;
  return { keyId, issuerId, apiKeyBase64, appId };
}

async function resolveAscServerTimestampSeconds(fetchImpl = fetch) {
  try {
    const headRes = await fetchImpl('https://api.appstoreconnect.apple.com/v1/apps', {
      method: 'HEAD',
    });
    const dateHeader =
      typeof headRes?.headers?.get === 'function'
        ? headRes.headers.get('date')
        : null;
    if (dateHeader) {
      const parsedMs = Date.parse(dateHeader);
      if (!Number.isNaN(parsedMs) && parsedMs > 0) {
        return Math.floor(parsedMs / 1000);
      }
    }
  } catch {
    // Fall back to system clock when HEAD probe fails.
  }
  return Math.floor(Date.now() / 1000);
}

export async function queryHighestAscBuild({
  env = process.env,
  fetchImpl = fetch,
} = {}) {
  const { keyId, issuerId, apiKeyBase64, appId } = resolveAppleApiCredentials(env);

  if (!keyId || !issuerId || !apiKeyBase64) {
    console.warn(
      `[nightly-dispatch] App Store Connect credentials not set, using baseline ${BASELINE_BUILD_NUMBER}.`,
    );
    return { maxBuild: BASELINE_BUILD_NUMBER, versions: [] };
  }

  try {
    const nowSeconds = await resolveAscServerTimestampSeconds(fetchImpl);
    const privateKey = createPrivateKey(Buffer.from(apiKeyBase64, 'base64'));
    const header = Buffer.from(
      JSON.stringify({ alg: 'ES256', kid: keyId, typ: 'JWT' }),
    ).toString('base64url');
    const claims = Buffer.from(
      JSON.stringify({
        iss: issuerId,
        iat: nowSeconds,
        exp: nowSeconds + 300,
        aud: 'appstoreconnect-v1',
      }),
    ).toString('base64url');
    const token = `${header}.${claims}.${sign(
      'sha256',
      Buffer.from(`${header}.${claims}`),
      {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
      },
    ).toString('base64url')}`;

    const url = `https://api.appstoreconnect.apple.com/v1/builds?filter[app]=${encodeURIComponent(
      appId,
    )}&include=preReleaseVersion&sort=-uploadedDate&limit=50`;

    let res = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      res = await fetchImpl(url, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
        },
      });
      if (res.ok || res.status < 500) {
        break;
      }
      await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
    }

    if (!res || !res.ok) {
      const status = res ? res.status : 'network-error';
      console.warn(
        `[nightly-dispatch] ASC API returned HTTP ${status}; falling back to baseline ${BASELINE_BUILD_NUMBER}.`,
      );
      return { maxBuild: BASELINE_BUILD_NUMBER, versions: [] };
    }

    const data = await res.json();
    const builds = Array.isArray(data?.data) ? data.data : [];
    const included = Array.isArray(data?.included) ? data.included : [];
    let maxBuild = 0;
    for (const b of builds) {
      const v = parseInt(b?.attributes?.version, 10);
      if (!Number.isNaN(v) && v > maxBuild) {
        maxBuild = v;
      }
    }
    const versions = [];
    for (const item of included) {
      if (item?.type === 'preReleaseVersions') {
        const parsed = parseSemverTag(String(item?.attributes?.version || ''));
        if (parsed) {
          versions.push(parsed.version);
        }
      }
    }
    return {
      maxBuild: maxBuild > 0 ? maxBuild : BASELINE_BUILD_NUMBER,
      versions,
    };
  } catch (err) {
    console.warn(`[nightly-dispatch] ASC query error: ${err.message}`);
    return { maxBuild: BASELINE_BUILD_NUMBER, versions: [] };
  }
}

function githubHeaders(token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'leapterm-twice-daily-dispatcher',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

function extractReleaseInputsFromLog(logText) {
  const text = String(logText || '');
  const buildOnlyMatch = text.match(/"build_only"\s*:\s*(true|false)/);
  if (buildOnlyMatch && buildOnlyMatch[1] === 'true') {
    return null;
  }
  const versionMatch = text.match(/"version"\s*:\s*"(\d{1,4}\.\d{1,4}\.\d{1,4})"/);
  const buildMatch = text.match(/"build_number"\s*:\s*"(\d{1,4})"/);
  if (!versionMatch && !buildMatch) {
    return null;
  }
  return {
    version: versionMatch ? versionMatch[1] : null,
    buildNumber: buildMatch ? parseInt(buildMatch[1], 10) : null,
  };
}

export async function collectGithubReleaseState({
  publicRepo = PUBLIC_RELEASE_REPO,
  sourceRepo = '',
  token = '',
  fetchImpl = fetch,
} = {}) {
  const versions = new Set();
  let maxBuildNumber = 0;
  const activeFullReleaseRunIds = [];
  const headers = githubHeaders(token);

  const inspectRepoReleases = async (repoSlug) => {
    if (!repoSlug) return;
    try {
      const res = await fetchImpl(
        `https://api.github.com/repos/${repoSlug}/releases?per_page=100`,
        { headers },
      );
      if (!res.ok) return;
      const releases = await res.json();
      if (!Array.isArray(releases)) return;
      for (const rel of releases) {
        const parsed = parseSemverTag(String(rel?.tag_name || ''));
        if (!parsed) continue;
        versions.add(parsed.version);
        if (parsed.buildNumber && parsed.buildNumber > maxBuildNumber) {
          maxBuildNumber = parsed.buildNumber;
        }
      }
    } catch {
      // Best-effort discovery across repositories.
    }
  };

  await inspectRepoReleases(publicRepo);
  if (sourceRepo && token) {
    await inspectRepoReleases(sourceRepo);
  }

  try {
    const runsRes = await fetchImpl(
      `https://api.github.com/repos/${publicRepo}/actions/workflows/release.yml/runs?per_page=10`,
      { headers },
    );
    if (runsRes.ok) {
      const runsJson = await runsRes.json();
      const runs = Array.isArray(runsJson?.workflow_runs)
        ? runsJson.workflow_runs
        : [];
      const relevantRuns = runs.filter(
        (r) =>
          r?.status === 'in_progress' ||
          r?.status === 'queued' ||
          (r?.status === 'completed' && r?.conclusion === 'success'),
      );
      for (const run of relevantRuns.slice(0, 5)) {
        const isActiveRun = run?.status === 'in_progress' || run?.status === 'queued';
        const jobsRes = await fetchImpl(
          `https://api.github.com/repos/${publicRepo}/actions/runs/${run.id}/jobs?per_page=30`,
          { headers },
        );
        if (!jobsRes.ok) continue;
        const jobsJson = await jobsRes.json();
        const jobs = Array.isArray(jobsJson?.jobs) ? jobsJson.jobs : [];
        const approvalJob = jobs.find(
          (j) => j?.name === 'Validate release request automatically',
        );
        if (isActiveRun && approvalJob && approvalJob.conclusion !== 'skipped') {
          activeFullReleaseRunIds.push(run.id);
        }
        const inputJob = jobs.find(
          (j) =>
            j?.conclusion === 'success' &&
            (j?.name === 'Validate release request automatically' ||
              j?.name === 'Resolve release inputs'),
        );
        if (!inputJob) continue;
        const logRes = await fetchImpl(
          `https://api.github.com/repos/${publicRepo}/actions/jobs/${inputJob.id}/logs`,
          { headers },
        );
        if (!logRes.ok) continue;
        const logText = await logRes.text();
        const extracted = extractReleaseInputsFromLog(logText);
        if (extracted && isActiveRun && !activeFullReleaseRunIds.includes(run.id)) {
          activeFullReleaseRunIds.push(run.id);
        }
        if (extracted?.version) {
          versions.add(extracted.version);
        }
        if (
          extracted?.buildNumber &&
          Number.isSafeInteger(extracted.buildNumber) &&
          extracted.buildNumber > maxBuildNumber
        ) {
          maxBuildNumber = extracted.buildNumber;
        }
      }
    }
  } catch {
    // Best-effort active workflow inspection.
  }

  return {
    versions: [...versions],
    maxBuildNumber,
    activeFullReleaseRunIds,
  };
}

export async function resolveDispatchPlan({
  env = process.env,
  fetchImpl = fetch,
} = {}) {
  const target = (trimEnv(env, 'TARGET') || 'all').toLowerCase();
  if (!ALLOWED_SCHEDULED_TARGETS.includes(target)) {
    throw new Error(
      `Unsupported scheduled release target "${target}"; expected one of: ${ALLOWED_SCHEDULED_TARGETS.join(', ')}`,
    );
  }

  const explicitVersion = trimEnv(env, 'VERSION') || trimEnv(env, 'INPUT_VERSION');
  const explicitBuild =
    trimEnv(env, 'BUILD_NUMBER') || trimEnv(env, 'INPUT_BUILD_NUMBER');
  const explicitSourceSha = trimEnv(env, 'INPUT_SOURCE_SHA');
  const publicRepo = trimEnv(env, 'PUBLIC_RELEASE_REPO') || PUBLIC_RELEASE_REPO;
  const sourceRepo = trimEnv(env, 'SOURCE_REPOSITORY');
  const token =
    trimEnv(env, 'GH_TOKEN') ||
    trimEnv(env, 'PRIVATE_RELEASE_TOKEN') ||
    trimEnv(env, 'GITHUB_TOKEN');

  const [ascState, ghState] = await Promise.all([
    queryHighestAscBuild({ env, fetchImpl }),
    collectGithubReleaseState({
      publicRepo,
      sourceRepo,
      token,
      fetchImpl,
    }),
  ]);

  let version;
  if (explicitVersion) {
    const parsed = parseSemverTag(explicitVersion);
    if (!parsed) {
      throw new Error(`Invalid explicit release version: "${explicitVersion}"`);
    }
    version = parsed.version;
  } else {
    version = computeNextPatchVersion([
      ...ghState.versions,
      ...ascState.versions,
    ]);
  }

  let buildNumber;
  if (explicitBuild) {
    if (!/^[1-9]\d{0,3}$/.test(explicitBuild)) {
      throw new Error(`Invalid explicit build_number: "${explicitBuild}"`);
    }
    buildNumber = parseInt(explicitBuild, 10);
  } else {
    const highestKnown = Math.max(
      ascState.maxBuild || 0,
      ghState.maxBuildNumber || 0,
      BASELINE_BUILD_NUMBER,
    );
    buildNumber = highestKnown + 1;
  }

  return {
    publicRepo,
    target,
    version,
    buildNumber,
    sourceSha: explicitSourceSha,
    activeFullReleaseRunIds: ghState.activeFullReleaseRunIds || [],
  };
}

export function buildNightlyDispatchArgs({
  publicRepo = PUBLIC_RELEASE_REPO,
  target = 'all',
  version,
  buildNumber,
  sourceSha = '',
} = {}) {
  const normalizedTarget = String(target || 'all').trim().toLowerCase();
  if (!ALLOWED_SCHEDULED_TARGETS.includes(normalizedTarget)) {
    throw new Error(
      `Unsupported scheduled release target "${target}"; expected one of: ${ALLOWED_SCHEDULED_TARGETS.join(', ')}`,
    );
  }
  const parsedVersion = parseSemverTag(String(version || ''));
  if (!parsedVersion) {
    throw new Error(`Invalid release version "${version}"`);
  }
  const normalizedBuild = String(buildNumber || '').trim();
  if (!/^[1-9]\d{0,3}$/.test(normalizedBuild)) {
    throw new Error(`Invalid release build_number "${buildNumber}"`);
  }

  const iosAction = normalizedTarget === 'fast' ? 'skip' : 'upload';
  const includeSelfhost = normalizedTarget === 'all' ? 'true' : 'false';

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
    'build_only=false',
    '-f',
    `verify_target=${normalizedTarget}`,
    '-f',
    `version=${parsedVersion.version}`,
    '-f',
    `build_number=${normalizedBuild}`,
    '-f',
    `ios_action=${iosAction}`,
    '-f',
    'automatic_release=false',
    '-f',
    `include_selfhost=${includeSelfhost}`,
    '-f',
    'auto_promote=true',
  ];

  if (sourceSha) {
    if (!/^[0-9a-f]{40}$/i.test(sourceSha)) {
      throw new Error(`Invalid explicit source_sha "${sourceSha}"`);
    }
    args.push('-f', `source_sha=${sourceSha.toLowerCase()}`);
  }

  return args;
}

export async function main({
  env = process.env,
  fetchImpl = fetch,
  execFileImpl = execFileSync,
} = {}) {
  const plan = await resolveDispatchPlan({ env, fetchImpl });

  if (
    trimEnv(env, 'GITHUB_EVENT_NAME') === 'schedule' &&
    trimEnv(env, 'FORCE_DISPATCH') !== 'true' &&
    !trimEnv(env, 'VERSION') &&
    !trimEnv(env, 'INPUT_VERSION') &&
    Array.isArray(plan.activeFullReleaseRunIds) &&
    plan.activeFullReleaseRunIds.length > 0
  ) {
    console.log(
      `[nightly-dispatch] Active full release.yml run(s) already in progress (${plan.activeFullReleaseRunIds.join(', ')}); skipping duplicate scheduled dispatch.`,
    );
    return { ...plan, skipped: true };
  }

  console.log(
    `[nightly-dispatch] Source selection: ${plan.sourceSha || 'latest main (resolved by release.yml)'}`,
  );
  console.log(`[nightly-dispatch] Version:          ${plan.version}`);
  console.log(`[nightly-dispatch] Build Number:     ${plan.buildNumber}`);
  console.log(`[nightly-dispatch] Verify Target:    ${plan.target}`);

  const args = buildNightlyDispatchArgs(plan);
  console.log(`[nightly-dispatch] Running: gh ${args.join(' ')}`);

  if (env.DRY_RUN === 'true' || process.argv.includes('--dry-run')) {
    console.log('[nightly-dispatch] Dry run complete; skipping actual dispatch.');
    return plan;
  }

  execFileImpl('gh', args, {
    stdio: 'inherit',
    env,
  });
  console.log(
    '[nightly-dispatch] Successfully dispatched twice-daily release & TestFlight workflow!',
  );
  return plan;
}

const isDirectRun =
  Boolean(process.argv[1]) &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isDirectRun) {
  main().catch((err) => {
    console.error(
      '[nightly-dispatch] Fatal:',
      err instanceof Error ? err.message : String(err),
    );
    process.exit(1);
  });
}
