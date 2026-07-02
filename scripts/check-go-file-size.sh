#!/usr/bin/env bash
# Pre-commit hook: warn if any .go file exceeds 1000 lines of code.
# TODO: change "exit 0" to "exit $failed" once all files are under the limit.
MAX_LINES=1000
failed=0
for f in "$@"; do
    lines=$(wc -l < "$f")
    if [ "$lines" -gt "$MAX_LINES" ]; then
        echo "WARNING: $f has $lines lines (max $MAX_LINES)"
        failed=1
    fi
done
exit 0
