#!/bin/bash
# Tests for hack/lib/tekton-paths.sh, run under the options
# hack/resolve-konflux-images.sh uses, plus inherit_errexit so that an unguarded
# failure inside a function shows up as a wrong exit status.
#
#   hack/test-tekton-paths.sh hack/lib/tekton-paths.sh [<full clone of master>]
#
# Without a clone, it only needs bash, awk and git. With one, it also checks the
# real .tekton pipelines and decisions, as of master on 2026-10-16.
set -euo pipefail
shopt -s inherit_errexit

lib=$(realpath "$1")
real=${2:+$(realpath "$2")}
# shellcheck source=/dev/null
source "$lib"
repo=quay.io/redhat-user-workloads/ocp-isc-tenant

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
err=$work/stderr
passed=0
failed=0

# check <name> <status> <stdout, or * for any> <command>...: run the command and
# compare its exit status and stdout.
check() {
  local name=$1 want_status=$2 want_out=$3 out status=0
  shift 3
  out=$("$@" 2>"$err") || status=$?
  if [[ $status == "$want_status" && ( $want_out == '*' || $out == "$want_out" ) ]]; then
    passed=$((passed + 1))
    echo "PASS $name"
  else
    failed=$((failed + 1))
    echo "FAIL $name: status $status (want $want_status), stdout [$out], stderr [$(<"$err")]"
  fi
}

# pipeline <name> <annotation line>...: write .tekton/<name> with the lines as
# its on-cel-expression annotation.
pipeline() {
  local name=$1
  shift
  {
    echo 'apiVersion: tekton.dev/v1'
    echo 'kind: PipelineRun'
    echo 'metadata:'
    echo '  annotations:'
    printf '%s\n' "$@"
    echo '    pipelinesascode.tekton.dev/max-keep-runs: "3"'
    echo '  name: demo-on-pull-request'
  } >".tekton/$name"
}

patterns() { tekton_patterns "$1" | paste -sd ' '; }

mkdir -p "$work/fixtures/.tekton"
cd "$work/fixtures"

echo "== Reading triggers"
pipeline plain.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && target_branch == "master" && ( "pkg/**/*.go".pathChanged() || "Makefile".pathChanged() )'
check "one-line plain value" 0 'pkg/**/*.go Makefile' patterns .tekton/plain.yaml
pipeline plain-multi.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "push" && target_branch == "master"' '      && ( "main.go".pathChanged() || "vendor/***".pathChanged() )'
check "plain value over two lines" 0 'main.go vendor/***' patterns .tekton/plain-multi.yaml
pipeline folded.yaml '    pipelinesascode.tekton.dev/on-cel-expression: >-' '      event == "pull_request" &&' '      ( "pkg/**/*.go".pathChanged() ||' "        'tests/***'.pathChanged() )"
check "folded block, both quote styles" 0 'pkg/**/*.go tests/***' patterns .tekton/folded.yaml
pipeline literal.yaml '    pipelinesascode.tekton.dev/on-cel-expression: |' '      event == "pull_request"' '      && ( "a/*".pathChanged() )' ''
check "literal block with a blank line after" 0 'a/*' patterns .tekton/literal.yaml
pipeline squoted.yaml "    pipelinesascode.tekton.dev/on-cel-expression: 'event == \"pull_request\" && ( \"it''s/*\".pathChanged() )'"
check "single-quoted YAML value" 0 "it's/*" patterns .tekton/squoted.yaml
pipeline dquoted.yaml '    pipelinesascode.tekton.dev/on-cel-expression: "event == \"pull_request\" && ( \"x/*\".pathChanged() || \"y\".pathChanged() )"'
check "double-quoted YAML value" 0 'x/* y' patterns .tekton/dquoted.yaml
pipeline raw.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( r"x/*".pathChanged() )'
check "CEL raw string" 0 'x/*' patterns .tekton/raw.yaml
pipeline crlf.yaml $'    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "x".pathChanged() )\r'
check "CRLF line endings" 0 'x' patterns .tekton/crlf.yaml
pipeline nested.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "a".pathChanged() || ( "b".pathChanged() || "c".pathChanged() ) ) && target_branch == "master"'
check "nested || group, more conditions after" 0 'a b c' patterns .tekton/nested.yaml

echo "== Refusing triggers it can't read exactly"
pipeline files-all.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && files.all.exists(f, f.startsWith("pkg/"))'
check "files.all" 2 '' tekton_patterns .tekton/files-all.yaml
pipeline no-paths.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && target_branch == "master"'
check "no pathChanged()" 2 '' tekton_patterns .tekton/no-paths.yaml
pipeline negated.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && !( "docs/*".pathChanged() || "a".pathChanged() )'
check "negated group" 2 '' tekton_patterns .tekton/negated.yaml
pipeline negated-one.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "a".pathChanged() || !"docs/*".pathChanged() )'
check "one negated call" 2 '' tekton_patterns .tekton/negated-one.yaml
pipeline and.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "a".pathChanged() && "b".pathChanged() )'
check "calls joined by &&" 2 '' tekton_patterns .tekton/and.yaml
pipeline or-rest.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "a".pathChanged() ) || event == "push"'
check "group ORed with something else" 2 '' tekton_patterns .tekton/or-rest.yaml
pipeline or-before.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "push" || ( "a".pathChanged() )'
check "group ORed with what's before" 2 '' tekton_patterns .tekton/or-before.yaml
pipeline braces.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "pkg/{a,b}.go".pathChanged() )'
check "{a,b} pattern" 2 '' tekton_patterns .tekton/braces.yaml
pipeline class.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "pkg/[ab].go".pathChanged() )'
check "[ab] pattern" 2 '' tekton_patterns .tekton/class.yaml
pipeline escaped.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "a\\b".pathChanged() || "c".pathChanged() )'
check "escape in a CEL string" 2 '' tekton_patterns .tekton/escaped.yaml
pipeline empty.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "".pathChanged() )'
check "empty pattern" 2 '' tekton_patterns .tekton/empty.yaml
pipeline comment.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "a".pathChanged() ) # comment'
check "trailing YAML comment" 2 '' tekton_patterns .tekton/comment.yaml
pipeline dup.yaml '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && ( "a".pathChanged() )' '    pipelinesascode.tekton.dev/on-cel-expression: event == "push"'
check "two on-cel-expressions" 2 '' tekton_patterns .tekton/dup.yaml
pipeline none.yaml '    pipelinesascode.tekton.dev/on-target-branch: "[master]"'
check "no on-cel-expression" 2 '' tekton_patterns .tekton/none.yaml
pipeline dq-escape.yaml '    pipelinesascode.tekton.dev/on-cel-expression: "event == \"pull_request\" && ( \"a\\tb\".pathChanged() )"'
check "other YAML escape" 2 '' tekton_patterns .tekton/dq-escape.yaml
pipeline unterminated.yaml "    pipelinesascode.tekton.dev/on-cel-expression: 'event == \"pull_request\" && ( \"a\".pathChanged() )"
check "unterminated quote" 2 '' tekton_patterns .tekton/unterminated.yaml
check "missing file" 2 '' tekton_patterns .tekton/missing.yaml

echo "== Finding pipelines by output image"
rm -f .tekton/*
printf '  params:\n  - name: output-image\n    value: %s\n' "$repo/comp-dev:on-pr-{{revision}}" >.tekton/comp-dev-pull-request.yaml
printf '  params:\n  - name: output-image\n    value: "%s"\n' "$repo/comp-dev:{{revision}}" >.tekton/comp-dev-push.yaml
printf '  params:\n  - name: output-image\n    value: %s\n' "$repo/comp-release:on-pr-{{revision}}" >.tekton/comp-release-1-10-pull-request.yaml
check "pull-request pipeline" 0 .tekton/comp-dev-pull-request.yaml tekton_pipeline comp-dev pull-request
check "push pipeline, quoted value" 0 .tekton/comp-dev-push.yaml tekton_pipeline comp-dev push
check "release-branch naming" 0 .tekton/comp-release-1-10-pull-request.yaml tekton_pipeline comp-release pull-request
check "no pipeline" 2 '' tekton_pipeline comp-other pull-request
check "prefix of another component" 2 '' tekton_pipeline comp pull-request
cp .tekton/comp-dev-pull-request.yaml .tekton/copy-pull-request.yaml
check "two pipelines for one image" 2 '' tekton_pipeline comp-dev pull-request
check "unknown kind" 2 '' tekton_pipeline comp-dev nightly
pipeline comp-bad-pull-request.yaml '  params:' '  - name: output-image' "    value: $repo/comp-bad:on-pr-{{revision}}" '    pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && files.all.exists(f, true)'
check "strict_tag refuses an unreadable trigger" 2 '' strict_tag comp-bad 0123456789012345678901234567890123456789 0123456789012345678901234567890123456789

echo "== Matching files like Konflux"
P=('pkg/**/*.go' 'tests/***' '*Makefile*' 'build/bin/*' 'main.go' 'v?r/x')
check "pkg/**/*.go" 0 'pkg/**/*.go' path_matches pkg/controller/a/b.go "${P[@]}"
check "* crosses / like gobwas" 0 'build/bin/*' path_matches build/bin/sub/dir/x "${P[@]}"
check "*Makefile* in a subdirectory" 0 '*Makefile*' path_matches images/x/Makefile "${P[@]}"
check "? is one character" 0 'v?r/x' path_matches var/x "${P[@]}"
check "a .md under pkg" 1 '' path_matches pkg/README.md "${P[@]}"
check "hack/ script" 1 '' path_matches hack/resolve-konflux-images.sh "${P[@]}"
check "top-level .go needs pkg/x/" 1 '' path_matches pkg/x.go "${P[@]}"

echo "== Changes in a git history"
git init -q "$work/git"
cd "$work/git"
git config user.email t@example.com
git config user.name t
commit() { mkdir -p "$(dirname "$1")"; echo "$2" >"$1"; git add -A; git commit -qm "$3"; }
commit README.md 1 "docs"
commit pkg/a/a.go 1 "operator change"
op=$(git rev-parse HEAD)
commit hack/x.sh 1 "hack only"
commit 'dir with space/new
line.txt' 1 "odd file name"
base=$(git rev-parse HEAD)
git checkout -qb pr
commit hack/y.sh 1 "PR: hack only"
pr_hack=$(git rev-parse HEAD)
commit pkg/b/b.go 1 "PR: operator change"
pr_op=$(git rev-parse HEAD)
git checkout -q -
git merge -q --no-ff -m "Merge PR" "$pr_op"
merge=$(git rev-parse HEAD)
commit docs/z.md 1 "docs after the merge"
tip=$(git rev-parse HEAD)
P=('pkg/**/*.go' 'tests/***')
check "PR that changes the sources" 0 'pkg/b/b.go (pkg/**/*.go)' changed_match "$base" "$pr_op" "${P[@]}"
check "PR that doesn't" 1 '' changed_match "$base" "$pr_hack" "${P[@]}"
check "odd file names don't break the list" 1 '' changed_match "$op" "$base" "${P[@]}"
check "unknown commit" 2 '' changed_match "$base" 0123456789012345678901234567890123456789 "${P[@]}"
check "walk skips non-matching commits" 0 "$merge" last_matching_commit "$tip" "${P[@]}"
check "merge counts as one first-parent commit" 0 "$merge" last_matching_commit "$merge" "${P[@]}"
check "walk from a hack-only base" 0 "$op" last_matching_commit "$base" "${P[@]}"
check "nothing matches" 1 '' last_matching_commit "$tip" 'nothing/*'
check "unknown tip" 2 '' last_matching_commit 0123456789012345678901234567890123456789 "${P[@]}"

if [[ -n $real ]]; then
  echo "== The real pipelines and decisions on master"
  cd "$real"
  op_pr=$(tekton_pipeline compliance-operator-dev pull-request)
  op_push=$(tekton_pipeline compliance-operator-dev push)
  check "operator pull-request pipeline" 0 .tekton/compliance-operator-dev-pull-request.yaml tekton_pipeline compliance-operator-dev pull-request
  check "operator push pipeline" 0 .tekton/compliance-operator-dev-push.yaml tekton_pipeline compliance-operator-dev push
  # Capture first: mapfile < <(...) would hide a failure as an empty list.
  pr_list=$(tekton_patterns "$op_pr")
  push_list=$(tekton_patterns "$op_push")
  mapfile -t P <<<"$pr_list"
  mapfile -t Q <<<"$push_list"
  check "15 operator patterns" 0 15 echo "${#P[@]}"
  check "push watches the same" 0 "${P[*]}" echo "${Q[*]}"
  for c in compliance-operator-openscap-dev compliance-operator-must-gather-dev; do
    for k in pull-request push; do
      check "$c $k patterns readable" 0 '*' tekton_patterns "$(tekton_pipeline "$c" "$k")"
    done
  done
  check "#1456 changes the operator" 0 '*' changed_match d9602cd60421484ae523ed4287a06144970e1d85 29e2b1b6b014e25f71d3296256cca0353651a9f0 "${P[@]}"
  check "#1479 doesn't" 1 '' changed_match e5e873f20115e9c2e5377a6d91ea8ad4df44874b 746307d3bcf6a05481cf0208fb8f0c847735fe0b "${P[@]}"
  check "base e5e873f20 is its own build" 0 e5e873f20115e9c2e5377a6d91ea8ad4df44874b last_matching_commit e5e873f20115e9c2e5377a6d91ea8ad4df44874b "${Q[@]}"
  check "base 474b813a0 walks back to #1472" 0 6bb659bc83ed08a9005fa5a27a92f3082eeb0624 last_matching_commit 474b813a095bbaa3c0798fd281fd1922a61e1137 "${Q[@]}"
  check "strict_tag: #1456 gets its own build" 0 on-pr-29e2b1b6b014e25f71d3296256cca0353651a9f0 strict_tag compliance-operator-dev d9602cd60421484ae523ed4287a06144970e1d85 29e2b1b6b014e25f71d3296256cca0353651a9f0
  check "strict_tag: #1479 gets its base's build" 0 e5e873f20115e9c2e5377a6d91ea8ad4df44874b strict_tag compliance-operator-dev e5e873f20115e9c2e5377a6d91ea8ad4df44874b 746307d3bcf6a05481cf0208fb8f0c847735fe0b
  check "strict_tag: no PR, base 474b813a0" 0 6bb659bc83ed08a9005fa5a27a92f3082eeb0624 strict_tag compliance-operator-dev 474b813a095bbaa3c0798fd281fd1922a61e1137
  check "strict_tag: unknown component" 2 '' strict_tag compliance-operator-nope 474b813a095bbaa3c0798fd281fd1922a61e1137
  check "strict_tag: unknown base" 2 '' strict_tag compliance-operator-dev 0123456789012345678901234567890123456789 29e2b1b6b014e25f71d3296256cca0353651a9f0
fi

echo "$passed passed, $failed failed"
(( failed == 0 ))
