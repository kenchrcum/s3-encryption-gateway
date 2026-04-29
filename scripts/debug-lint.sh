#!/usr/bin/env bash
# V1.0-SEC-18 — linter gate: forbid fmt.Printf in debug.Enabled blocks
# to prevent leaking metadata previews in debug logs.

set -euo pipefail

echo "Checking for forbidden fmt.Printf in debug.Enabled blocks..."

matches=$(grep -rn 'fmt\.Printf.*DEBUG' internal/ || true)

if [ -n "$matches" ]; then
    echo "FAIL: found forbidden fmt.Printf debug patterns:"
    echo "$matches"
    exit 1
fi

echo "PASS: no forbidden fmt.Printf debug patterns found."
