#!/bin/bash
# resolve-konflux-images.sh — Print the Konflux builds of images to test with.
#
#   hack/resolve-konflux-images.sh [--strict] <component>...
#
# For each Konflux component (e.g. compliance-operator-dev), this prints the
# pull spec of its build to test with.
#
# With --strict, the script uses git history and .tekton pipeline definitions to
# determine the exact build to test with:
#   - If the PR changes the component's sources, the PR's own build is used.
#   - If the PR doesn't change them, the script walks the base branch to find
#     the newest commit whose sources changed, and uses that commit's push build.
# This ensures the PR's code is actually tested, never a stale branch tag.
#
# Without --strict, the script uses the PR build if Konflux started one, or the
# branch tag (KONFLUX_TAG) otherwise.
#
# CI jobs test with these images:
#
#   IMAGE_FROM_CI=$(hack/resolve-konflux-images.sh --strict compliance-operator-dev)
#   OPENSCAP_IMAGE=$(hack/resolve-konflux-images.sh compliance-operator-openscap-dev)
#   MUST_GATHER_IMAGE=$(hack/resolve-konflux-images.sh compliance-operator-must-gather-dev)
#
# Jobs for other repositories can run the non-strict path from GitHub:
#
#   curl -fsSL https://raw.githubusercontent.com/ComplianceAsCode/compliance-operator/master/hack/resolve-konflux-images.sh |
#     bash -s -- compliance-operator-dev
#
# Environment:
#   KONFLUX_REPO          Quay repository (default: quay.io/redhat-user-workloads/ocp-isc-tenant)
#   KONFLUX_SHA           PR head commit (default: PULL_PULL_SHA when this repo)
#   KONFLUX_BASE_SHA      Base commit (default: PULL_BASE_SHA when this repo)
#   KONFLUX_TAG           Branch tag for non-strict images (default: PULL_BASE_REF or master)
#   KONFLUX_WAIT_SECONDS  How long to wait for builds to start/finish (default: 300)
#   REPO_OWNER/REPO_NAME  Set by Prow; guards PULL_* defaults
#   JOB_TYPE              Set by Prow; batch is rejected in strict mode

set -euo pipefail

repo=${KONFLUX_REPO:-quay.io/redhat-user-workloads/ocp-isc-tenant}
wait_seconds=${KONFLUX_WAIT_SECONDS:-300}
strict=

# Parse --strict flag.
if [[ ${1:-} == --strict ]]; then
  strict=1
  shift
fi

if [[ $# -eq 0 ]]; then
  echo "usage: $0 [--strict] <component>..." >&2
  exit 2
fi
if [[ $repo != quay.io/* ]]; then
  echo "KONFLUX_REPO must be on quay.io: $repo" >&2
  exit 2
fi
# Validate KONFLUX_WAIT_SECONDS.
if [[ ! $wait_seconds =~ ^[0-9]+$ ]]; then
  echo "KONFLUX_WAIT_SECONDS must be whole seconds: $wait_seconds" >&2
  exit 2
fi

# Use PULL_* defaults only when the Prow job is for this repository. In
# openshift/release rehearsals and other repositories' jobs, PULL_* describes
# that other repository.
if [[ "${REPO_OWNER:-}/${REPO_NAME:-}" == "ComplianceAsCode/compliance-operator" ]]; then
  sha=${KONFLUX_SHA:-${PULL_PULL_SHA:-}}
  base_sha=${KONFLUX_BASE_SHA:-${PULL_BASE_SHA:-}}
  tag=${KONFLUX_TAG:-${PULL_BASE_REF:-master}}
else
  sha=${KONFLUX_SHA:-}
  base_sha=${KONFLUX_BASE_SHA:-}
  tag=${KONFLUX_TAG:-master}
fi

# In strict mode without an explicit base, use the checkout's HEAD.
# Fail hard if git fails instead of silently falling back to :master.
if [[ -n $strict && -z $base_sha ]]; then
  if ! base_sha=$(git rev-parse --verify 'HEAD^{commit}'); then
    echo "--strict needs this repository's git history, and git failed (above)" >&2
    exit 1
  fi
fi

# Source tekton-paths.sh only for strict mode.
if [[ -n $strict ]]; then
  lib="$(dirname "$0")/lib/tekton-paths.sh"
  if [[ ! -f $lib ]]; then
    echo "Cannot use --strict without a checkout: $lib not found" >&2
    exit 1
  fi
  # shellcheck source=lib/tekton-paths.sh
  source "$lib"
fi

# ---- Helpers ----

# need_commit <sha> <description>: fail if the checkout lacks the commit,
# showing git's own error and detecting shallow clones.
need_commit() {
  local err
  if ! err=$(git cat-file -e "$1^{commit}" 2>&1); then
    [[ $(git rev-parse --is-shallow-repository 2>/dev/null) == true ]] &&
      err="$err (the clone is shallow)"
    echo "The checkout lacks $2 $1: $err" >&2
    exit 1
  fi
}

# ---- Quay API helpers ----

# has <component> <tag> [active]: whether Quay has the tag, or ever had it.
# Exits when Quay can't be reached, so that an outage doesn't look like a
# missing build.
has() {
  local out
  out=$(curl -fsS --max-time 30 --retry 5 --retry-all-errors \
    "https://quay.io/api/v1/repository/${repo#quay.io/}/$1/tag/?specificTag=$2${3:+&onlyActiveTags=true}") || {
    echo "Could not get the tags of $repo/$1 from Quay" >&2
    exit 1
  }
  [[ $out == *'"name"'* ]]
}

# tag_start_ts <component> <tag>: print the start_ts epoch of a tag, or nothing.
tag_start_ts() {
  local out ts
  out=$(curl -fsS --max-time 30 --retry 3 --retry-all-errors \
    "https://quay.io/api/v1/repository/${repo#quay.io/}/$1/tag/?specificTag=$2" 2>/dev/null) || return 0
  ts=${out#*'"start_ts"'}
  [[ $ts != "$out" ]] || return 0
  ts=${ts#*:}; ts=${ts%%[,\}]*}; ts=${ts//[[:space:]]/}
  [[ $ts =~ ^[0-9]+$ ]] && printf '%s\n' "$ts"
}

# pipeline_name <pipeline_file>: the pipeline's metadata.name, for /test hints.
pipeline_name() {
  awk '
    /^metadata:/ { m = 1; next }
    m && /^[^ \t]/ { m = 0 }
    m && /^  name:/ {
      sub(/^  name:[[:space:]]*/, "")
      sub(/\r$/, "")
      if (/^".*"$/ || /^\047.*\047$/) $0 = substr($0, 2, length($0) - 2)
      print; exit
    }' "$1"
}

# check_run_hint <commit_sha> <pipeline_name>: best-effort GitHub API lookup
# for the Konflux check run. Prints a hint line, or nothing if the lookup
# fails. Never fails itself. Always queries ComplianceAsCode/compliance-operator
# because REPO_OWNER/REPO_NAME point to the rehearsal repo in rehearsals.
check_run_hint() {
  local cr_repo="ComplianceAsCode/compliance-operator"
  local out found='' conclusion='' details_url='' run_status='' line v
  out=$(curl -fsS --max-time 10 \
    "https://api.github.com/repos/$cr_repo/commits/$1/check-runs" 2>/dev/null) || return 0
  while IFS= read -r line; do
    if [[ $line == *'"name"'*"/ $2\""* ]]; then
      found=1; continue
    fi
    if [[ -n $found ]]; then
      if [[ $line == *'"conclusion"'* ]]; then
        v=${line#*'"conclusion"'}; v=${v#*'"'}; conclusion=${v%%'"'*}
      elif [[ $line == *'"details_url"'* ]]; then
        v=${line#*'"details_url"'}; v=${v#*'"'}; details_url=${v%%'"'*}
      elif [[ $line == *'"status"'* && -z $run_status ]]; then
        v=${line#*'"status"'}; v=${v#*'"'}; run_status=${v%%'"'*}
      fi
      [[ $line == *'}'* && -n $conclusion$run_status ]] && break
    fi
  done <<<"$out"
  [[ -n $found ]] || return 0
  if [[ $conclusion == failure && -n $details_url ]]; then
    echo "The Konflux build failed: $details_url"
  elif [[ $run_status == in_progress || $run_status == queued ]]; then
    echo "It is still running; /retest when it finishes."
  fi
}

# wait_for_tag <component> <tag>: poll until the tag is active, using
# exponential backoff (10s, 20s, 40s, 60s, ...) capped at 60s within the
# caller's shared budget ($waited / $wait_seconds).
# Returns 0 = active, 1 = .git tag expired/inactive, 2 = timed out.
# shellcheck disable=SC2154 # $waited and $wait_seconds are from the caller.
wait_for_tag() {
  local component=$1 wtag=$2 delay=10
  while :; do
    has "$component" "$wtag" active && return 0
    has "$component" "$wtag.git" active || return 1
    (( waited < wait_seconds )) || return 2
    (( delay <= wait_seconds - waited )) || delay=$(( wait_seconds - waited ))
    sleep "$delay"
    waited=$(( waited + delay ))
    delay=$(( delay * 2 > 60 ? 60 : delay * 2 ))
  done
}

# await_build <component> <tag>: wait for a Konflux build and handle all
# error cases with appropriate messages and rebuild hints. Uses a fresh
# $waited counter (one budget per component).
await_build() {
  local component=$1 atag=$2 image="$repo/$1:$2"
  local pfile pn rebuild_msg waited=0 ws=0

  # Determine the pipeline file and name for hints.
  if [[ $atag == on-pr-* ]]; then
    pfile=$(tekton_pipeline "$component" pull-request 2>/dev/null) || true
  else
    pfile=$(tekton_pipeline "$component" push 2>/dev/null) || true
  fi
  pn=
  [[ -z ${pfile:-} ]] || { pn=$(pipeline_name "$pfile") || true; }

  # Build the rebuild hint: /test for PR builds, re-run for push builds.
  if [[ $atag == on-pr-* ]]; then
    rebuild_msg="Comment \"/test ${pn:-$component-on-pull-request}\" to rebuild it, then /retest."
  else
    rebuild_msg="Re-run the push build of $atag in Konflux."
  fi

  # Already active?
  has "$component" "$atag" active && return 0

  # Build in progress?
  if has "$component" "$atag.git"; then
    # Use Quay start_ts as primary signal: if .git tag is older than ~45
    # minutes with no image, the build almost certainly failed — fail at once
    # instead of burning the full wait budget.
    local ts now age
    ts=$(tag_start_ts "$component" "$atag.git")
    if [[ -n $ts ]]; then
      now=$(date +%s)
      age=$(( now - ts ))
      if (( age > 2700 )) && ! has "$component" "$atag" active; then
        echo "$image: the Konflux build started $((age / 60)) minutes ago without producing an image; it has almost certainly failed." >&2
        if [[ -n ${pn:-} ]]; then
          local extra
          extra=$(check_run_hint "${atag#on-pr-}" "$pn") || true
          [[ -z ${extra:-} ]] || echo "$extra" >&2
        fi
        echo "$rebuild_msg" >&2
        exit 1
      fi
    fi
    wait_for_tag "$component" "$atag" || ws=$?
    case $ws in
      0) return 0 ;;
      1)
        echo "$image has expired." >&2
        echo "$rebuild_msg" >&2
        exit 1
        ;;
      2)
        echo "Konflux hasn't finished building $image after $((wait_seconds / 60)) minutes." >&2
        if [[ -n ${pn:-} ]]; then
          local extra2
          extra2=$(check_run_hint "${atag#on-pr-}" "$pn") || true
          [[ -z ${extra2:-} ]] || echo "$extra2" >&2
        fi
        echo "$rebuild_msg" >&2
        exit 1
        ;;
    esac
  fi

  # PR build that hasn't started yet: wait for it to appear.
  if [[ $atag == on-pr-* ]]; then
    local delay=30
    while (( waited < wait_seconds )); do
      if has "$component" "$atag.git"; then
        ws=0
        wait_for_tag "$component" "$atag" || ws=$?
        case $ws in
          0) return 0 ;;
          1)
            echo "$image has expired." >&2
            echo "$rebuild_msg" >&2
            exit 1
            ;;
          2)
            echo "Konflux hasn't finished building $image after $((wait_seconds / 60)) minutes." >&2
            echo "$rebuild_msg" >&2
            exit 1
            ;;
        esac
      fi
      (( delay <= wait_seconds - waited )) || delay=$(( wait_seconds - waited ))
      sleep "$delay"
      waited=$(( waited + delay ))
    done
    echo "Konflux hasn't started building $image after $((wait_seconds / 60)) minutes." >&2
    echo "$rebuild_msg" >&2
    exit 1
  fi

  # Push build that doesn't exist — include remedy.
  echo "$image, the build of base commit $atag (the newest that changes $component's sources), doesn't exist; its Konflux push build may have failed." >&2
  echo "$rebuild_msg" >&2
  exit 1
}

# ---- Non-strict resolve ----

# resolve <component>: print the build, using the PR build if Konflux started
# one, or the branch tag otherwise. Checks that the tag is active.
resolve() {
  local component=$1
  if [[ -n $sha ]] && has "$component" "on-pr-$sha.git"; then
    local waited=0 ws=0
    wait_for_tag "$component" "on-pr-$sha" || ws=$?
    case $ws in
      0) echo "$repo/$component:on-pr-$sha"; return ;;
      1)
        echo "$repo/$component:on-pr-$sha has expired: /test $component-on-pull-request rebuilds it" >&2
        exit 1
        ;;
      2)
        if has "$component" "on-pr-$sha.git" active; then
          echo "Konflux is still building $repo/$component:on-pr-$sha after $((wait_seconds / 60)) minutes; the PipelineRun may be unusually slow — check its status" >&2
        else
          echo "Konflux build of $repo/$component:on-pr-$sha appears to have failed (PipelineRun finished without producing an image)" >&2
        fi
        exit 1
        ;;
    esac
  fi
  if ! has "$component" "$tag" active; then
    echo "$repo/$component:$tag doesn't exist. Set KONFLUX_TAG, or check the Konflux push builds for $tag." >&2
    exit 1
  fi
  echo "$repo/$component:$tag"
}

# ---- Strict resolve ----

# resolve_strict <component>: print the exact build the job must test with,
# determined from git history and .tekton pipeline definitions. Delegates the
# decision logic to strict_tag() from tekton-paths.sh, and the waiting/error
# handling to await_build().
resolve_strict() {
  local component=$1 tag

  # Batch jobs test several PRs together; no single build matches.
  if [[ ${JOB_TYPE:-} == batch ]]; then
    echo "--strict is not supported for batch jobs: a batch tests several PRs together, so no single Konflux build matches" >&2
    exit 1
  fi

  # Verify the checkout has the required commits.
  [[ -z $sha ]] || need_commit "$sha" "the PR head"
  need_commit "$base_sha" "the base"

  # If Konflux already started a PR build (covers manual /test too), use it.
  if [[ -n $sha ]] && has "$component" "on-pr-$sha.git"; then
    echo "Konflux built this PR's $component, so it's tested with that build" >&2
    tag=on-pr-$sha
  else
    # Call strict_tag() for the decision: which tag to test with.
    tag=$(strict_tag "$component" "$base_sha" "$sha") || exit 1
  fi

  # Merge skew warning: if the base commit used for the build isn't an
  # ancestor of the PR head, master changed sources after the PR branched.
  if [[ -n $sha && $tag != on-pr-* ]]; then
    if ! git merge-base --is-ancestor "$tag" "$sha" 2>/dev/null; then
      echo "Note: master changed $component's sources after this PR branched. A rebase tests them together." >&2
    fi
  fi

  await_build "$component" "$tag"
  echo "$repo/$component:$tag"
}

# ---- Main loop ----

for component; do
  if [[ -n $strict ]]; then
    resolve_strict "$component"
  else
    resolve "$component"
  fi
done
