#!/usr/bin/env node
import { execFileSync } from 'node:child_process';

export const VALID_TRACKS = Object.freeze([
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

export function parseTag(rawTag) {
  if (!rawTag || typeof rawTag !== 'string') {
    throw new Error('Tag must be a non-empty string');
  }
  const tag = rawTag.trim().replace(/^refs\/tags\//, '');
  if (!tag) {
    throw new Error('Invalid empty tag');
  }

  // Extract semantic version digits (e.g. 0.1.1, 1.2.3)
  const versionMatch = tag.match(/(\d+\.\d+\.\d+)/);
  if (!versionMatch) {
    throw new Error(`Tag "${tag}" does not contain a valid semver version (e.g. 0.1.1)`);
  }
  const version = versionMatch[1];

  // Detect track from tag
  const lower = tag.toLowerCase();
  let track = 'all';
  for (const candidate of ['windows', 'macos', 'android', 'linux', 'ios', 'web', 'fast', 'slow']) {
    if (lower.includes(candidate)) {
      track = candidate;
      break;
    }
  }

  const buildOnly = !lower.includes('prod') && !lower.includes('publish') && !lower.includes('full');
  const autoPromote = lower.includes('promote');

  return {
    version,
    track,
    buildOnly,
    autoPromote,
    originalTag: tag,
  };
}

export function buildDispatchArguments({
  parsed,
  buildNumber = process.env.GITHUB_RUN_NUMBER || '1',
  repo = process.env.GITHUB_REPOSITORY || 'omnisolo-llc/leapterm-release',
  ref = 'main',
}) {
  return [
    'workflow',
    'run',
    'release.yml',
    '-R',
    repo,
    '--ref',
    ref,
    '-f',
    'release_route=option1',
    '-f',
    `build_only=${parsed.buildOnly}`,
    '-f',
    `verify_target=${parsed.track}`,
    '-f',
    `version=${parsed.version}`,
    '-f',
    `build_number=${buildNumber}`,
    '-f',
    `auto_promote=${parsed.autoPromote}`,
  ];
}

export async function dispatchTagFlow({
  tag = process.env.GITHUB_REF_NAME || process.env.GITHUB_REF || '',
  buildNumber = process.env.GITHUB_RUN_NUMBER || '1',
  repo = process.env.GITHUB_REPOSITORY || 'omnisolo-llc/leapterm-release',
  token = process.env.PRIVATE_RELEASE_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '',
  execFileImpl = execFileSync,
} = {}) {
  const parsed = parseTag(tag);
  console.log(`[Tag Flow] Tag "${parsed.originalTag}" resolved: version=${parsed.version}, track=${parsed.track}, buildOnly=${parsed.buildOnly}`);
  const args = buildDispatchArguments({ parsed, buildNumber, repo });
  console.log(`[Tag Flow] Executing: gh ${args.join(' ')}`);
  const env = {
    ...process.env,
    GH_TOKEN: token,
  };
  execFileImpl('gh', args, { env, stdio: 'inherit' });
  return parsed;
}

if (process.argv[1] && process.argv[1].endsWith('tag-flow-dispatch.mjs')) {
  dispatchTagFlow().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
