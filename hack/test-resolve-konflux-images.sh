#!/bin/bash
# Tests for hack/resolve-konflux-images.sh.
#
# Most cases run the script in a scratch git repository with its own .tekton
# pipelines, against a fake Quay (curl and sleep on PATH), and check the image
# it prints, its exit code and its message. The last cases run it on this
# repository's own .tekton pipelines and history.

set -euo pipefail

# CI checkouts can belong to another user, which git refuses by default.
git() {
	command git -c safe.directory='*' "$@"
}

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
passed=0 failed=0
Q=quay.io/redhat-user-workloads/ocp-isc-tenant

# The fake Quay has the tags listed in $tmp/quay/<component>, plus those in
# <component>.later once the script has slept. With $tmp/quay/all it has every
# tag; with $tmp/quay/down every request fails. It only answers queries for
# active tags, so an expired build can't count.
mkdir -p "$tmp/bin" "$tmp/quay"
cat >"$tmp/bin/curl" <<'EOF'
#!/bin/bash
url=${*: -1}
[[ ! -e $QUAY/down ]] || exit 7
[[ $url == *'&onlyActiveTags=true' ]] || exit 99
component=${url%/tag/*} component=${component##*/}
tag=${url#*specificTag=} tag=${tag%%&*}
echo "$component $tag" >>"$QUAY/requests"
if [[ -e $QUAY/all ]] || grep -qxF "$tag" "$QUAY/$component" 2>/dev/null; then
	echo "{\"tags\": [{\"name\": \"$tag\"}], \"page\": 1, \"has_additional\": false}"
else
	echo '{"tags": [], "page": 1, "has_additional": false}'
fi
EOF
cat >"$tmp/bin/sleep" <<'EOF'
#!/bin/bash
echo "$1" >>"$QUAY/sleeps"
for later in "$QUAY"/*.later; do
	[[ ! -e $later ]] || { cat "$later" >>"${later%.later}"; rm "$later"; }
done
EOF
chmod +x "$tmp/bin/curl" "$tmp/bin/sleep"

# quay <component> <tag>...: tags the fake Quay has.
quay() {
	local component=$1
	shift
	printf '%s\n' "$@" >>"$tmp/quay/$component"
}

# later <component> <tag>...: tags it has once the script has slept.
later() {
	local component=$1
	shift
	printf '%s\n' "$@" >>"$tmp/quay/$component.later"
}

reset_quay() {
	rm -rf "$tmp/quay"
	mkdir -p "$tmp/quay"
}

# pipeline <name> <event> <paths>: write .tekton/<name>.yaml, triggered for the
# event (pull_request or push) on master by the given paths expression.
pipeline() {
	mkdir -p .tekton
	cat >".tekton/$1.yaml" <<EOF
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  annotations:
    pipelinesascode.tekton.dev/max-keep-runs: "3"
    pipelinesascode.tekton.dev/on-cel-expression: event == "$2" && target_branch == "master" && ( $3 )
  name: $1
EOF
}

# tick: move the clock for the next commit, so commits have distinct times and
# git can't order them by chance.
clock=1700000000
tick() {
	clock=$((clock + 60))
	export GIT_AUTHOR_DATE="@$clock +0000" GIT_COMMITTER_DATE="@$clock +0000"
}

# change <message> <file>...: commit a change to each file; print the commit.
change() {
	local message=$1 file
	shift
	for file; do
		mkdir -p "$(dirname "$file")"
		echo "$message" >>"$file"
	done
	git add -A
	tick
	git commit -qm "$message"
	git rev-parse HEAD
}

# run <dir> [VAR=value...] -- <component>...: run the script in a repository,
# unaffected by the caller's Prow and Konflux variables.
run() {
	local dir=$1 vars=()
	shift
	while [[ $1 != -- ]]; do
		vars+=("$1")
		shift
	done
	shift
	rc=0
	out=$(cd "$dir" && env -u KONFLUX_SHA -u KONFLUX_BASE_SHA -u KONFLUX_REPO -u KONFLUX_WAIT_SECONDS \
		-u PULL_PULL_SHA -u PULL_BASE_SHA -u REPO_OWNER -u REPO_NAME -u JOB_TYPE \
		PATH="$tmp/bin:$PATH" QUAY="$tmp/quay" KONFLUX_WAIT_SECONDS=0 "${vars[@]}" \
		hack/resolve-konflux-images.sh "$@" 2>"$tmp/err") || rc=$?
	err=$(<"$tmp/err")
}

# report <name> <command>...: count the case as passed if the command succeeds.
report() {
	local name=$1
	shift
	if "$@"; then
		passed=$((passed + 1))
		echo "ok   $name"
	else
		failed=$((failed + 1))
		printf 'FAIL %s\n  exit: %s\n  stdout: %s\n  stderr: %s\n' "$name" "$rc" "$out" "$err"
	fi
}

# is <exit code> <stdout> [<text the message has>]: whether the last run matches.
is() {
	[[ $rc == "$1" && $out == "$2" && $err == *"${3:-}"* ]]
}

# The scratch repository has an operator (op) and a scanner (scap) component.
mkdir -p "$tmp/repo/hack"
cd "$tmp/repo"
git init -qb master
git config user.email test@example.com
git config user.name test
git config commit.gpgsign false
git config core.hooksPath /dev/null
cp "$here/resolve-konflux-images.sh" hack/
op='".tekton/op-*.yaml".pathChanged() || "pkg/**/*.go".pathChanged() || "images/op/***".pathChanged() || "build/bin/*".pathChanged() || "*Makefile*".pathChanged()'
scap='".tekton/scap-*.yaml".pathChanged() || "images/scap/***".pathChanged()'
pipeline op-pull-request pull_request "$op"
pipeline op-push push "$op"
pipeline scap-pull-request pull_request "$scap"
pipeline scap-push push "$scap"
first=$(change first pkg/a.go images/scap/Containerfile docs/a.md)
op_change=$(change "op change" pkg/sub/b.go)
base=$(change "docs change" docs/b.md)
git checkout -qb pr-op
pr_op=$(change "PR changes op" pkg/sub/c.go)
git checkout -qb pr-docs master
pr_docs=$(change "PR changes docs" docs/c.md)
git checkout -qb pr-old "$first"
pr_old=$(change "PR from before op change" docs/old.md)
git checkout -qb pr-move master
git mv pkg/sub/b.go docs/b.go.txt
tick
git commit -qm "PR moves a watched file out"
pr_move=$(git rev-parse HEAD)
git checkout -q master
r=$tmp/repo

reset_quay
quay op "on-pr-$pr_op" "$op_change"
quay scap "$first"
run "$r" KONFLUX_SHA="$pr_op" KONFLUX_BASE_SHA="$base" -- op scap
report "A PR that changes a watched file is tested with its own build, and the others with base builds" \
	is 0 "$Q/op:on-pr-$pr_op
$Q/scap:$first" "op: the PR changes pkg/sub/c.go (pkg/**/*.go), so the job uses the PR's build"

run "$r" KONFLUX_SHA="$pr_docs" KONFLUX_BASE_SHA="$base" -- op scap
report "A PR that changes no watched file gets the newest base build" \
	is 0 "$Q/op:$op_change
$Q/scap:$first" "op: the job uses the build of $op_change, the newest base commit that changes pkg/sub/b.go (pkg/**/*.go)"

reset_quay
quay op "$op_change"
run "$r" KONFLUX_SHA="$pr_old" KONFLUX_BASE_SHA="$base" -- op
report "Base changes made after the PR branched aren't the PR's" is 0 "$Q/op:$op_change"

reset_quay
quay op "on-pr-$pr_move"
run "$r" KONFLUX_SHA="$pr_move" KONFLUX_BASE_SHA="$base" -- op
report "Moving a watched file away counts as changing it" \
	is 0 "$Q/op:on-pr-$pr_move" "the PR changes pkg/sub/b.go (pkg/**/*.go)"

reset_quay
quay op "$op_change" "$first"
run "$r" KONFLUX_SHA="$pr_op" KONFLUX_BASE_SHA="$base" -- op
report "A missing PR build fails instead of falling back to the base build" \
	is 1 "" "$Q/op:on-pr-$pr_op isn't on Quay after 0 seconds. Check the PR's Konflux check: Konflux waits for /ok-to-test on PRs from outside the organization, and \"/test op-on-pull-request\" rebuilds a failed or expired build."

reset_quay
later op "on-pr-$pr_op"
run "$r" KONFLUX_SHA="$pr_op" KONFLUX_BASE_SHA="$base" KONFLUX_WAIT_SECONDS=300 -- op
report "It waits for a PR build that is still running" is 0 "$Q/op:on-pr-$pr_op"
report "... sleeping once, for 30 seconds" test "$(paste -sd, "$tmp/quay/sleeps")" = 30

reset_quay
run "$r" KONFLUX_SHA="$pr_op" KONFLUX_BASE_SHA="$base" KONFLUX_WAIT_SECONDS=45 -- op
report "It gives up after KONFLUX_WAIT_SECONDS" is 1 "" "isn't on Quay after 45 seconds"
report "... sleeping 30 and 15 seconds, and checking once more after the last sleep" \
	test "$(paste -sd, "$tmp/quay/sleeps") $(wc -l <"$tmp/quay/requests")" = "30,15 3"

reset_quay
quay op "$first"
run "$r" KONFLUX_SHA="$pr_docs" KONFLUX_BASE_SHA="$base" -- op
report "A missing base build fails instead of falling back to an older one" \
	is 1 "" "$Q/op:$op_change isn't on Quay after 0 seconds. Check the Konflux push build of $op_change."

reset_quay
quay op "$op_change"
run "$r" -- op
report "Without a PR or base, the checkout's HEAD is the base" is 0 "$Q/op:$op_change"

run "$r" KONFLUX_REPO=quay.io/example/builds -- op
report "KONFLUX_REPO sets the Quay repository" is 0 "quay.io/example/builds/op:$op_change"

reset_quay
quay op "on-pr-$pr_op"
run "$r" REPO_OWNER=ComplianceAsCode REPO_NAME=compliance-operator PULL_PULL_SHA="$pr_op" PULL_BASE_SHA="$base" -- op
report "This repository's Prow jobs use PULL_PULL_SHA and PULL_BASE_SHA" is 0 "$Q/op:on-pr-$pr_op"

reset_quay
quay op "$op_change"
run "$r" REPO_OWNER=openshift REPO_NAME=release PULL_PULL_SHA=0123456789012345678901234567890123456789 \
	PULL_BASE_SHA=0123456789012345678901234567890123456789 -- op
report "openshift/release rehearsals ignore that repository's PULL_*" is 0 "$Q/op:$op_change"

run "$r" KONFLUX_SHA=0123456789012345678901234567890123456789 -- op
report "A commit the checkout lacks fails" is 1 "" "The checkout lacks commit 0123456789012345678901234567890123456789"

run "$r" JOB_TYPE=batch -- op
report "Batch jobs fail" is 1 "" "A batch job tests several PRs together"

run "$r" KONFLUX_WAIT_SECONDS=5m -- op
report "KONFLUX_WAIT_SECONDS must be whole seconds" is 1 "" "KONFLUX_WAIT_SECONDS must be whole seconds: 5m"

run "$r" --
report "It needs a component" is 1 "" "usage:"

run "$r" -- nope
report "A component without pipelines fails" is 1 "" ".tekton/nope-push.yaml doesn't exist or has no on-cel-expression"

touch "$tmp/quay/down"
run "$r" -- op
report "A Quay outage fails instead of looking like a missing build" is 1 "" "Could not get the tags of $Q/op from Quay"
rm "$tmp/quay/down"

star=$(change "star change" build/bin/sub/tool)
reset_quay
quay op "$star"
run "$r" -- op
report "* matches /, as it does in Konflux" \
	is 0 "$Q/op:$star" "the newest base commit that changes build/bin/sub/tool (build/bin/*)"

git checkout -qb side
change "side change" images/op/Containerfile >/dev/null
git checkout -q master
tick
git merge -q --no-ff side -m "merge side"
merge=$(git rev-parse HEAD)
reset_quay
quay op "$merge"
run "$r" -- op
report "A merge commit counts with its change against its first parent" \
	is 0 "$Q/op:$merge" "the newest base commit that changes images/op/Containerfile (images/op/***)"

git checkout -qb revert
change "revert side: add" images/op/extra >/dev/null
git rm -q images/op/extra
tick
git commit -qm "revert side: remove"
git checkout -q master
tick
git merge -q --no-ff revert -m "merge revert"
reset_quay
quay op "$merge"
run "$r" -- op
report "Commits only on a merged side branch don't count" \
	is 0 "$Q/op:$merge" "the newest base commit that changes images/op/Containerfile"

reset_quay
quay scap "$first"
run "$r" -- scap
report "The newest base build can be many commits back" \
	is 0 "$Q/scap:$first" "scap: the job uses the build of $first, the newest base commit that changes .tekton/scap-pull-request.yaml"

# bad <paths>: commit an op push pipeline triggered by <paths>; undo it with
# git reset --hard "$good".
good=$(git rev-parse HEAD)
bad() {
	pipeline op-push push "$1"
	tick
	git commit -qam "bad pipeline"
}
bad '"{pkg,cmd}/**".pathChanged()'
run "$r" -- op
report "Brace patterns fail" is 1 "" ".tekton/op-push.yaml: unsupported pattern {pkg,cmd}/**"
bad '"pkg/[ab].go".pathChanged()'
run "$r" -- op
report "Bracket patterns fail" is 1 "" "unsupported pattern pkg/[ab].go"
bad '"pkg/***".pathChanged() || !"docs/***".pathChanged()'
run "$r" -- op
report "Negated paths fail" is 1 "" "the trigger isn't a list of watched paths"
bad '"pkg/***".pathChanged()'
sed -i 's/&& ( /\&\& body.pull_request.draft == false \&\& ( /' .tekton/op-push.yaml
git commit -qam "bad pipeline"
run "$r" -- op
report "Other conditions fail" is 1 "" "the trigger isn't a list of watched paths"
bad ''
run "$r" -- op
report "A trigger without paths fails" is 1 "" "the trigger isn't a list of watched paths"
git reset -q --hard "$good"

# Konflux reads a PR's pipelines from its head, so a PR that changes its own
# trigger is judged by the new one.
git checkout -qb pr-trigger master
pipeline op-pull-request pull_request '"docs/***".pathChanged()'
pr_trigger=$(change "PR watches docs" docs/trigger.md)
git checkout -q master
reset_quay
quay op "on-pr-$pr_trigger"
run "$r" KONFLUX_SHA="$pr_trigger" KONFLUX_BASE_SHA="$good" -- op
report "A PR is judged by the trigger in its own head" \
	is 0 "$Q/op:on-pr-$pr_trigger" "the PR changes docs/trigger.md (docs/***)"

reset_quay
quay op "$merge"
run "$r" GIT_TEST_ASSUME_DIFFERENT_OWNER=1 -- op
report "A checkout that belongs to another user works, as CI checkouts can" is 0 "$Q/op:$merge"

git clone -q --depth 1 "file://$r" "$tmp/shallow"
run "$tmp/shallow" -- scap
report "A shallow clone without the build's commit says it is shallow" \
	is 1 "" "none of the newest 1000 commits of $(git rev-parse HEAD) changes the files its push pipeline watches (the clone is shallow)"
run "$tmp/shallow" KONFLUX_SHA="$pr_op" -- op
report "... as does a shallow clone without the PR head" is 1 "" "The checkout lacks commit $pr_op (the clone is shallow)"

# This repository's own pipelines and history, when this is a git checkout.
if root=$(git -C "$here" rev-parse --show-toplevel 2>/dev/null) && [[ -d $root/.tekton ]]; then
	reset_quay
	touch "$tmp/quay/all"
	mapfile -t components < <(cd "$root/.tekton" && for f in *-push.yaml; do echo "${f%-push.yaml}"; done)

	# images <tag regex>: whether the last run printed one image per component,
	# in order, each with a tag that matches.
	images() {
		local i=0 line
		[[ $rc == 0 ]] || return 1
		while IFS= read -r line; do
			[[ $line =~ ^$Q/${components[i]}:$1$ ]] || return 1
			i=$((i + 1))
		done <<<"$out"
		[[ $i == "${#components[@]}" ]]
	}

	run "$root" -- "${components[@]}"
	report "This repository's push pipelines all parse, and each has a base build (${#components[@]} components)" \
		images '[0-9a-f]{40}'
	if git -C "$root" cat-file -e HEAD~1 2>/dev/null; then
		run "$root" KONFLUX_SHA="$(git -C "$root" rev-parse HEAD)" KONFLUX_BASE_SHA="$(git -C "$root" rev-parse HEAD~1)" -- \
			"${components[@]}"
		report "This repository's pull-request pipelines all parse" images '(on-pr-)?[0-9a-f]{40}'
	fi
else
	echo "skip This repository's pipelines: not a git checkout"
fi

echo "$passed passed, $failed failed"
[[ $failed -eq 0 ]]
