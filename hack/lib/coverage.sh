#!/usr/bin/env bash
# Shared coverage helpers for check-coverage.sh and update-coverage-baseline.sh.

# Extract per-package coverage from go test output.
# Handles both plain and JSON (-json) formats:
#   plain: ok  	github.com/.../pkg	1.234s	coverage: 67.5% of statements
#   json:  {"Package":"github.com/.../pkg","Output":"coverage: 67.5% of statements\n"}
extract_coverage() {
    grep 'coverage:.*of statements' "$1" | while IFS= read -r line; do
        if [[ "$line" == "{"* ]]; then
            pkg=$(echo "$line" | sed 's/.*"Package":"\([^"]*\)".*/\1/')
        elif [[ "$line" == ok* ]]; then
            pkg=$(echo "$line" | awk '{print $2}')
        else
            continue
        fi
        pct=$(echo "$line" | sed 's/.*coverage: \([0-9.]*\)%.*/\1/')
        printf '%s\t%s\n' "$pkg" "$pct"
    done
}
