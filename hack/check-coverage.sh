#!/usr/bin/env bash
set -euo pipefail

TEST_OUTPUT="${1:?Usage: $0 <test-output-log> <baseline> <coverprofile>}"
BASELINE="${2:?Usage: $0 <test-output-log> <baseline> <coverprofile>}"
COVERPROFILE="${3:?Usage: $0 <test-output-log> <baseline> <coverprofile>}"

if [ ! -f "$BASELINE" ]; then
    echo "INFO: No coverage baseline found at $BASELINE — skipping check."
    exit 0
fi

if [ ! -f "$TEST_OUTPUT" ]; then
    echo "ERROR: Test output $TEST_OUTPUT not found."
    exit 1
fi

if [ ! -f "$COVERPROFILE" ]; then
    echo "ERROR: Coverprofile $COVERPROFILE not found."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# Compute per-package coverage from a coverprofile, excluding generated files.
extract_filtered_coverage() {
    local filtered
    filtered=$(mktemp)
    trap "rm -f $filtered" RETURN
    "${SCRIPT_DIR}/filter-coverage.sh" "$1" "$filtered"
    awk 'NR > 1 {
        split($1, a, ":")
        file = a[1]
        n = split(file, parts, "/")
        pkg = ""
        for (i = 1; i < n; i++) pkg = pkg (i > 1 ? "/" : "") parts[i]
        stmts = $2 + 0
        count = $3 + 0
        total[pkg] += stmts
        if (count > 0) covered[pkg] += stmts
    }
    END {
        for (pkg in total) {
            pct = (total[pkg] > 0) ? (covered[pkg] / total[pkg] * 100.0) : 0
            printf "%s\t%.1f\n", pkg, pct
        }
    }' "$filtered"
}

coverage=$(extract_filtered_coverage "$COVERPROFILE")

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
