#!/bin/sh
if [ -n "${LEAP_PYTHON_GUARD_LOG:-}" ]; then
  printf '%s\n' "$0" >> "$LEAP_PYTHON_GUARD_LOG"
fi
exit 97
