#!/usr/bin/env bash
set -euo pipefail

TEST_OUTPUT="${1:?Usage: $0 <test-output-log> <baseline>}"
BASELINE="${2:?Usage: $0 <test-output-log> <baseline>}"

if [ ! -f "$BASELINE" ]; then
    echo "INFO: No coverage baseline found at $BASELINE — skipping check."
    exit 0
fi

if [ ! -f "$TEST_OUTPUT" ]; then
    echo "ERROR: Test output $TEST_OUTPUT not found."
    exit 1
fi

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

coverage=$(extract_coverage "$TEST_OUTPUT")

fail=0
stale=0
while IFS=$'\t' read -r pkg baseline_pct; do
    [[ "$pkg" =~ ^#.*$ || -z "$pkg" ]] && continue

    current_pct=$(echo "$coverage" | awk -F'\t' -v p="$pkg" '$1 == p {print $2}')
    if [ -z "$current_pct" ]; then
        echo "WARN: Package $pkg is in baseline but has no coverage data (removed or has no tests)."
        continue
    fi

    regressed=$(awk "BEGIN { print ($baseline_pct > $current_pct) ? 1 : 0 }")
    if [ "$regressed" -eq 1 ]; then
        echo "FAIL: $pkg coverage dropped: ${baseline_pct}% -> ${current_pct}%"
        fail=1
    fi

    improved=$(awk "BEGIN { print ($current_pct > $baseline_pct) ? 1 : 0 }")
    if [ "$improved" -eq 1 ]; then
        echo "INFO: $pkg coverage improved: ${baseline_pct}% -> ${current_pct}%"
        stale=1
    fi
done < "$BASELINE"

while IFS=$'\t' read -r pkg pct; do
    if ! grep -q "^${pkg}	" "$BASELINE" 2>/dev/null; then
        echo "INFO: New package $pkg has ${pct}% coverage (not in baseline)."
        stale=1
    fi
done <<< "$coverage"

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "Coverage regression detected. Add or update unit tests to restore coverage."
    exit 1
fi

if [ "$stale" -ne 0 ]; then
    echo ""
    echo "Coverage baseline is out of date. Run 'make update-coverage-baseline' to update."
    exit 1
fi

echo "Coverage check passed."
