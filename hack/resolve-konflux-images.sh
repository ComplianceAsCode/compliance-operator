#!/bin/bash
# Print the Konflux build of each component that a CI job should test with:
#
#   IMAGE_FROM_CI=$(hack/resolve-konflux-images.sh compliance-operator-dev)
#
# A PR is tested with its own build of a component (on-pr-<head>) when it
# changes a file that the component's .tekton pull-request pipeline watches,
# which is the check Konflux makes before it builds. Otherwise the job uses the
# push build of the newest base commit that changed such a file, which is the
# image the base has. The image is the one the pipeline's output-image names.
# The script waits up to KONFLUX_WAIT_SECONDS for that build and fails if Quay
# doesn't have it. It never falls back to another image, so a job can't pass on
# an image that doesn't match the code it tests.
#
# Jobs name components as master does, so every branch runs the same command.
# Master's components end in -dev; on another branch the script uses that
# branch's component instead, with its own pipelines and image repository: on
# release-1.10, compliance-operator-dev is compliance-operator-release-1-10,
# which Konflux pushes to compliance-operator-release. Names that don't end in
# -dev are used as given.
#
# Konflux matches each "<pattern>".pathChanged() with gobwas/glob, where * also
# matches /. For patterns made of literal characters, * and ?, bash's
# [[ $file == $pattern ]] matches the same files; the script refuses other
# patterns, and triggers that aren't a plain list of watched paths for the
# job's branch.
#
# Environment:
#   PULL_PULL_SHA, PULL_BASE_SHA, PULL_BASE_REF
#                         set by Prow; used only in this repository's jobs
#   KONFLUX_SHA           the PR head, overriding PULL_PULL_SHA; without one the
#                         job tests the base
#   KONFLUX_BASE_SHA      the base, overriding PULL_BASE_SHA; default the
#                         checkout's HEAD
#   KONFLUX_BRANCH        the base's branch, overriding PULL_BASE_REF; default
#                         the branch that the base's push pipelines build
#   KONFLUX_WAIT_SECONDS  default 300

set -euo pipefail

fail() {
	echo "$*" >&2
	exit 1
}

# CI checkouts can belong to another user, which git refuses by default.
git() {
	command git -c safe.directory='*' "$@"
}

wait_seconds=${KONFLUX_WAIT_SECONDS:-300}
[[ $# -gt 0 ]] || fail "usage: $0 <component>..."
[[ $wait_seconds =~ ^[0-9]+$ ]] || fail "KONFLUX_WAIT_SECONDS must be whole seconds: $wait_seconds"
[[ ${JOB_TYPE:-} != batch ]] || fail "A batch job tests several PRs together, so no single Konflux build matches it"
cd "$(dirname "$0")/.."

# openshift/release rehearsals set PULL_* for their own PR, not this repository's.
if [[ ${REPO_OWNER:-}/${REPO_NAME:-} == ComplianceAsCode/compliance-operator ]]; then
	head=${KONFLUX_SHA:-${PULL_PULL_SHA:-}}
	base=${KONFLUX_BASE_SHA:-${PULL_BASE_SHA:-}}
	branch=${KONFLUX_BRANCH:-${PULL_BASE_REF:-}}
else
	head=${KONFLUX_SHA:-}
	base=${KONFLUX_BASE_SHA:-}
	branch=${KONFLUX_BRANCH:-}
fi
base=${base:-$(git rev-parse HEAD)}
shallow=
[[ $(git rev-parse --is-shallow-repository) == false ]] || shallow=" (the clone is shallow)"
for commit in $head $base; do
	git cat-file -e "$commit^{commit}" 2>/dev/null || fail "The checkout lacks commit $commit$shallow"
done
# Without a branch, such as in a rehearsal, the job tests the branch that the
# base's push pipelines build.
if [[ -z $branch ]]; then
	branch=$(git grep -h -o -E 'target_branch *== *"[^"]*"' "$base" -- '.tekton/*-push.yaml' |
		sed -E 's/.*"(.*)"/\1/' | sort -u) || true
	[[ -n $branch && $branch != *$'\n'* ]] ||
		fail "Set KONFLUX_BRANCH: the push pipelines in .tekton at $base don't build a single branch"
fi

# component <name>: the component's name on the job's branch.
component() {
	if [[ $branch != master && $1 == *-dev ]]; then
		echo "${1%-dev}-${branch//./-}"
	else
		echo "$1"
	fi
}

# watched <commit> <pipeline>: the path patterns that the trigger of
# .tekton/<pipeline> watches at the commit, one per line. Konflux reads a PR's
# pipelines from its head, and a push's from the pushed commit.
watched() {
	local spec=$1:.tekton/$2 yaml cel shape patterns pattern
	local re='^event=="(pull_request|push)"&&target_branch=="([^"]+)"&&\(\)$'
	# Read the file whole first: piped into grep -m1, git show can die of
	# SIGPIPE, and pipefail reports that as a failure.
	yaml=$(git show "$spec" 2>/dev/null) || fail "$spec doesn't exist"
	cel=$(grep -m1 'pipelinesascode.tekton.dev/on-cel-expression:' <<<"$yaml") ||
		fail "$spec has no on-cel-expression"
	cel=${cel#*on-cel-expression:}
	shape=$(sed -E 's/"[^"]*"\.pathChanged\(\)//g; s/\|\|//g; s/[[:space:]]//g' <<<"$cel")
	patterns=$(grep -o '"[^"]*"\.pathChanged()' <<<"$cel" | sed -E 's/^"//; s/"\.pathChanged\(\)$//') || true
	[[ -n $patterns && $shape =~ $re ]] ||
		fail "$spec: the trigger isn't a list of watched paths:$cel"
	[[ ${BASH_REMATCH[2]} == "$branch" ]] ||
		fail "$spec: the trigger is for ${BASH_REMATCH[2]}, not $branch"
	while IFS= read -r pattern; do
		case $pattern in
		*'['* | *'{'* | *\\*) fail "$spec: unsupported pattern $pattern" ;;
		esac
	done <<<"$patterns"
	echo "$patterns"
}

# output_image <commit> <pipeline>: the image that .tekton/<pipeline> at the
# commit pushes when it builds the commit, from its output-image parameter.
output_image() {
	local spec=$1:.tekton/$2 yaml value re='^quay\.io/[^:]+:(on-pr-)?\{\{revision\}\}$'
	yaml=$(git show "$spec" 2>/dev/null) || fail "$spec doesn't exist"
	value=$(sed -n '/^ *- name: output-image$/{n;s/^ *value: *//p;q;}' <<<"$yaml")
	[[ $value =~ $re ]] || fail "$spec has no output-image quay.io/<repository>:[on-pr-]{{revision}}: $value"
	echo "${value%%:*}:${BASH_REMATCH[1]}$1"
}

# matches <patterns> <files>: print the first file a pattern matches, with the
# pattern, or return 1 if none does.
matches() {
	local file pattern
	while IFS= read -r file; do
		while IFS= read -r pattern; do
			# shellcheck disable=SC2053 # $pattern is a glob on purpose.
			if [[ -n $file && $file == $pattern ]]; then
				echo "$file ($pattern)"
				return 0
			fi
		done <<<"$1"
	done <<<"$2"
	return 1
}

# newest_build <patterns>: the newest commit in the base's first-parent history
# whose own change touches a watched file. Konflux built it on push, and its
# build is the image the base has. A shallow clone's oldest commit seems to add
# every file, so the search stops there.
newest_build() {
	local line commit='' parents='' files='' why
	while IFS= read -r line; do
		if [[ $line == commit\ * ]]; then
			if [[ -n $commit ]]; then
				[[ -n $parents || -z $shallow ]] || return 1
				if why=$(matches "$1" "$files"); then
					echo "$commit $why"
					return 0
				fi
			fi
			read -r commit parents <<<"${line#commit }"
			files=
		elif [[ -n $line ]]; then
			files+=$line$'\n'
		fi
	done < <(git log --first-parent --diff-merges=first-parent --no-renames --max-count=1000 \
		--format='commit %H %P' --name-only "$base"; echo 'commit ')
	return 1
}

# on_quay <image>: whether Quay has the image's tag. Fails when Quay can't be
# reached, so an outage can't look like a missing build.
on_quay() {
	local repository=${1%:*} tags
	tags=$(curl -fsS --max-time 30 --retry 5 --retry-all-errors \
		"https://quay.io/api/v1/repository/${repository#quay.io/}/tag/?specificTag=${1##*:}&onlyActiveTags=true") ||
		fail "Could not get the tags of $repository from Quay"
	[[ $tags == *'"name"'* ]]
}

for name; do
	component=$(component "$name")
	[[ $component == "$name" ]] || echo "$name: $branch builds it as $component" >&2
	commit=
	if [[ -n $head ]]; then
		pipeline=$component-pull-request.yaml
		patterns=$(watched "$head" "$pipeline")
		fork=$(git merge-base "$base" "$head") || fail "The checkout has no common commit of $head and $base$shallow"
		changed=$(git diff --no-renames --name-only "$fork" "$head")
		if why=$(matches "$patterns" "$changed"); then
			commit=$head
			missing="Check the PR's Konflux check: Konflux waits for /ok-to-test on PRs from outside the organization, and \"/test $component-on-pull-request\" rebuilds a failed or expired build."
			echo "$component: the PR changes $why, so the job uses the PR's build" >&2
		fi
	fi
	if [[ -z $commit ]]; then
		pipeline=$component-push.yaml
		patterns=$(watched "$base" "$pipeline")
		found=$(newest_build "$patterns") ||
			fail "$component: none of the newest 1000 commits of $base changes the files its push pipeline watches$shallow"
		commit=${found%% *}
		missing="Check the Konflux push build of $commit."
		echo "$component: the job uses the build of $commit, the newest base commit that changes ${found#* }" >&2
	fi
	image=$(output_image "$commit" "$pipeline")
	waited=0
	until on_quay "$image"; do
		((waited < wait_seconds)) || fail "$image isn't on Quay after $wait_seconds seconds. $missing"
		delay=$((wait_seconds - waited < 30 ? wait_seconds - waited : 30))
		sleep "$delay"
		waited=$((waited + delay))
	done
	echo "$image"
done
