#!/usr/bin/env bash
set -euo pipefail

# Single source of truth for generated-file exclusion in coverage reports.
# To exclude a new generated file pattern, add it to GENERATED_FILE_PATTERNS.
GENERATED_FILE_PATTERNS='zz_generated|fake_impl'

COVERPROFILE="${1:?Usage: $0 <coverprofile-in> [coverprofile-out]}"
OUTPUT="${2:-/dev/stdout}"

if [ ! -f "$COVERPROFILE" ]; then
    echo "ERROR: Coverprofile $COVERPROFILE not found." >&2
    exit 1
fi

head -1 "$COVERPROFILE" > "$OUTPUT"
tail -n +2 "$COVERPROFILE" | grep -v -E "$GENERATED_FILE_PATTERNS" >> "$OUTPUT"
