#!/bin/bash
# Print the Konflux build of each component that a CI job should test with:
#
#   IMAGE_FROM_CI=$(hack/resolve-konflux-images.sh compliance-operator-dev)
#
# A PR is tested with its own build of a component (on-pr-<head>) when it
# changes a file that the component's .tekton pull-request pipeline watches,
# which is the check Konflux makes before it builds. Otherwise the job uses the
# push build of the newest base commit that changed such a file, which is the
# image the base has. The script waits up to KONFLUX_WAIT_SECONDS for that build
# and fails if Quay doesn't have it. It never falls back to another image, so a
# job can't pass on an image that doesn't match the code it tests.
#
# Konflux matches each "<pattern>".pathChanged() with gobwas/glob, where * also
# matches /. For patterns made of literal characters, * and ?, bash's
# [[ $file == $pattern ]] matches the same files; the script refuses other
# patterns, and triggers that aren't a plain list of watched paths.
#
# Environment:
#   PULL_PULL_SHA, PULL_BASE_SHA  set by Prow; used only in this repository's jobs
#   KONFLUX_SHA, KONFLUX_BASE_SHA the PR head and base, overriding PULL_*; without
#                                 a PR head the job tests the base, which defaults
#                                 to the checkout's HEAD
#   KONFLUX_REPO                  default quay.io/redhat-user-workloads/ocp-isc-tenant
#   KONFLUX_WAIT_SECONDS          default 300

set -euo pipefail

fail() {
	echo "$*" >&2
	exit 1
}

# CI checkouts can belong to another user, which git refuses by default.
git() {
	command git -c safe.directory='*' "$@"
}

repo=${KONFLUX_REPO:-quay.io/redhat-user-workloads/ocp-isc-tenant}
wait_seconds=${KONFLUX_WAIT_SECONDS:-300}
[[ $# -gt 0 ]] || fail "usage: $0 <component>..."
[[ $wait_seconds =~ ^[0-9]+$ ]] || fail "KONFLUX_WAIT_SECONDS must be whole seconds: $wait_seconds"
[[ ${JOB_TYPE:-} != batch ]] || fail "A batch job tests several PRs together, so no single Konflux build matches it"
cd "$(dirname "$0")/.."

# openshift/release rehearsals set PULL_* for their own PR, not this repository's.
if [[ ${REPO_OWNER:-}/${REPO_NAME:-} == ComplianceAsCode/compliance-operator ]]; then
	head=${KONFLUX_SHA:-${PULL_PULL_SHA:-}}
	base=${KONFLUX_BASE_SHA:-${PULL_BASE_SHA:-}}
else
	head=${KONFLUX_SHA:-}
	base=${KONFLUX_BASE_SHA:-}
fi
base=${base:-$(git rev-parse HEAD)}
shallow=
[[ $(git rev-parse --is-shallow-repository) == false ]] || shallow=" (the clone is shallow)"
for commit in $head $base; do
	git cat-file -e "$commit^{commit}" 2>/dev/null || fail "The checkout lacks commit $commit$shallow"
done

# watched <commit> <pipeline>: the path patterns that the trigger of
# .tekton/<pipeline> watches at the commit, one per line. Konflux reads a PR's
# pipelines from its head, and a push's from the pushed commit.
watched() {
	local spec=$1:.tekton/$2 cel shape patterns pattern
	local re='^event=="(pull_request|push)"&&target_branch=="[^"]+"&&\(\)$'
	cel=$(git show "$spec" 2>/dev/null | grep -m1 'pipelinesascode.tekton.dev/on-cel-expression:') ||
		fail "$spec doesn't exist or has no on-cel-expression"
	cel=${cel#*on-cel-expression:}
	shape=$(sed -E 's/"[^"]*"\.pathChanged\(\)//g; s/\|\|//g; s/[[:space:]]//g' <<<"$cel")
	patterns=$(grep -o '"[^"]*"\.pathChanged()' <<<"$cel" | sed -E 's/^"//; s/"\.pathChanged\(\)$//') || true
	[[ -n $patterns && $shape =~ $re ]] ||
		fail "$spec: the trigger isn't a list of watched paths:$cel"
	while IFS= read -r pattern; do
		case $pattern in
		*'['* | *'{'* | *\\*) fail "$spec: unsupported pattern $pattern" ;;
		esac
	done <<<"$patterns"
	echo "$patterns"
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

# on_quay <component> <tag>: whether Quay has an image with the tag. Fails
# when Quay can't be reached, so an outage can't look like a missing build.
on_quay() {
	local tags
	tags=$(curl -fsS --max-time 30 --retry 5 --retry-all-errors \
		"https://quay.io/api/v1/repository/${repo#quay.io/}/$1/tag/?specificTag=$2&onlyActiveTags=true") ||
		fail "Could not get the tags of $repo/$1 from Quay"
	[[ $tags == *'"name"'* ]]
}

for component; do
	tag=
	if [[ -n $head ]]; then
		patterns=$(watched "$head" "$component-pull-request.yaml")
		fork=$(git merge-base "$base" "$head") || fail "The checkout has no common commit of $head and $base$shallow"
		changed=$(git diff --no-renames --name-only "$fork" "$head")
		if why=$(matches "$patterns" "$changed"); then
			tag=on-pr-$head
			echo "$component: the PR changes $why, so the job uses the PR's build" >&2
		fi
	fi
	if [[ -z $tag ]]; then
		patterns=$(watched "$base" "$component-push.yaml")
		found=$(newest_build "$patterns") ||
			fail "$component: none of the newest 1000 commits of $base changes the files its push pipeline watches$shallow"
		tag=${found%% *}
		echo "$component: the job uses the build of $tag, the newest base commit that changes ${found#* }" >&2
	fi
	if [[ $tag == on-pr-* ]]; then
		missing="Check the PR's Konflux check: Konflux waits for /ok-to-test on PRs from outside the organization, and \"/test $component-on-pull-request\" rebuilds a failed or expired build."
	else
		missing="Check the Konflux push build of $tag."
	fi
	waited=0
	until on_quay "$component" "$tag"; do
		((waited < wait_seconds)) || fail "$repo/$component:$tag isn't on Quay after $wait_seconds seconds. $missing"
		delay=$((wait_seconds - waited < 30 ? wait_seconds - waited : 30))
		sleep "$delay"
		waited=$((waited + delay))
	done
	echo "$repo/$component:$tag"
done
