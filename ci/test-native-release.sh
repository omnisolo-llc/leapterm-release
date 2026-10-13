#!/usr/bin/env bash
# Native unit/local-Git/process tests, not an Apple device certificate.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
manifest="$here/native-release/Cargo.toml"
guard="$(mktemp -d)"
trap 'rm -rf -- "$guard"' EXIT
mkdir "$guard/bin"
export OMNI_PYTHON_GUARD_LOG="$guard/python-invocations"
for tool in python python2 python3 python3.12 python3.13 python3.14 pip pip3 pipx pypy pypy3 py; do
  printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$0" >> "$OMNI_PYTHON_GUARD_LOG"' 'exit 97' > "$guard/bin/$tool"
  chmod 700 "$guard/bin/$tool"
done
export PATH="$guard/bin:$PATH"
export CARGO_BUILD_JOBS=1
check() {
  local phase="$1"
  shift
  printf 'Native contract phase: %s\n' "$phase"
  if "$@" >>"$guard/bootstrap.log" 2>&1; then
    return 0
  else
    local status=$?
    printf 'Native contract failure phase: %s\n' "$phase" >&2
    printf 'Native contract command exit: %s\n' "$status" >&2
    while IFS= read -r -d '' source; do
      local target="${source##*/}"
      target="${target%.rs}"
      if [[ "$target" =~ ^[A-Za-z_][A-Za-z0-9_-]{0,127}$ ]]; then
        printf 'Native public target: %s\n' "$target"
      fi
      cat -- "$source"
      printf '\n'
    done < <(find "$here/native-release/src" "$here/native-release/tests" -type f -name '*.rs' -print0) > "$guard/public-identifiers.rs"
    awk -f "$here/native-failure-summary.awk" "$guard/public-identifiers.rs" "$guard/bootstrap.log" >&2
    echo 'Native contract check failed; raw compiler and test output remains private.' >&2
    if [[ -n "${DIAGNOSTICS_PUBLIC_KEY:-}" && -n "${RUNNER_TEMP:-}" ]]; then
      touch "$guard/task.log"
      node "$here/seal_diagnostics.cjs" "$guard" "$RUNNER_TEMP/encrypted-diagnostics/diagnostics.sealed" >/dev/null 2>&1 || true
    fi
    exit "$status"
  fi
}
if ! rustup run 1.95.0 cargo fmt --version >>"$guard/bootstrap.log" 2>&1 \
  || ! rustup run 1.95.0 cargo clippy --version >>"$guard/bootstrap.log" 2>&1; then
  check toolchain rustup toolchain install 1.95.0 --profile minimal --component rustfmt,clippy --no-self-update
fi
check version cargo +1.95.0 --version
check format cargo +1.95.0 fmt --manifest-path "$manifest" --check
check tests cargo +1.95.0 test --locked --manifest-path "$manifest" -- --test-threads=1
check clippy cargo +1.95.0 clippy --locked --all-targets --manifest-path "$manifest" -- -D warnings
sed -n '/^test result:/p' "$guard/bootstrap.log"
if [[ -e "$OMNI_PYTHON_GUARD_LOG" ]]; then
  echo 'A native test invoked a forbidden Python tool.' >&2
  exit 1
fi
echo 'Native suites passed with Python/pip commands blocked in PATH.'
