#!/bin/sh
if [ -n "${OMNI_PYTHON_GUARD_LOG:-}" ]; then
  printf '%s\n' "$0" >> "$OMNI_PYTHON_GUARD_LOG"
fi
exit 97
