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
if [[ -n $strict && -z $base_sha ]]; then
  base_sha=$(git rev-parse HEAD 2>/dev/null) || true
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
# fails. Never fails itself.
check_run_hint() {
  local cr_repo="${REPO_OWNER:-ComplianceAsCode}/${REPO_NAME:-compliance-operator}"
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

# wait_for_tag <component> <tag>: poll until the tag is active.
# Returns 0 = active, 1 = .git tag expired/inactive, 2 = timed out.
wait_for_tag() {
  local component=$1 wtag=$2 elapsed=0 delay
  for delay in 10 20 40; do
    has "$component" "$wtag" active && return 0
    has "$component" "$wtag.git" active || return 1
    sleep "$delay"
    elapsed=$((elapsed + delay))
  done
  while (( elapsed < wait_seconds )); do
    has "$component" "$wtag" active && return 0
    has "$component" "$wtag.git" active || return 1
    sleep 60
    elapsed=$((elapsed + 60))
  done
  return 2
}

# ---- Non-strict resolve ----

# resolve <component>: print the build, using the PR build if Konflux started
# one, or the branch tag otherwise. Checks that the tag is active.
resolve() {
  local component=$1
  if [[ -n $sha ]] && has "$component" "on-pr-$sha.git"; then
    local ws=0
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
# determined from git history and .tekton pipeline definitions.
resolve_strict() {
  local component=$1

  # Batch jobs test several PRs together; no single build matches.
  if [[ ${JOB_TYPE:-} == batch ]]; then
    echo "--strict is not supported for batch jobs: a batch tests several PRs together, so no single Konflux build matches" >&2
    exit 1
  fi

  if [[ -n $sha ]]; then
    # -- PR job: have a PR head commit --

    if [[ -z $base_sha ]]; then
      echo "--strict needs KONFLUX_BASE_SHA (or PULL_BASE_SHA) when KONFLUX_SHA is set" >&2
      exit 1
    fi
    # Verify the checkout has the required commits.
    if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
      echo "The checkout lacks commit $sha (the PR head). A full clone is needed for --strict" >&2
      exit 1
    fi
    if ! git cat-file -e "$base_sha^{commit}" 2>/dev/null; then
      echo "The checkout lacks commit $base_sha (the base). A full clone is needed for --strict" >&2
      exit 1
    fi

    # If Konflux already started a PR build (covers manual /test too), use it.
    if has "$component" "on-pr-$sha.git"; then
      local pfile_hint ws=0
      pfile_hint=$(tekton_pipeline "$component" pull-request 2>/dev/null) || true
      wait_for_tag "$component" "on-pr-$sha" || ws=$?
      case $ws in
        0) echo "$repo/$component:on-pr-$sha"; return ;;
        1)
          local pn=
          [[ -n ${pfile_hint:-} ]] && { pn=$(pipeline_name "$pfile_hint") || true; }
          echo "$repo/$component:on-pr-$sha has expired. Comment \"/test ${pn:-$component-on-pull-request}\" to rebuild it, then /retest." >&2
          exit 1
          ;;
        2)
          local mins=$((wait_seconds / 60))
          echo "Konflux hasn't finished building $repo/$component:on-pr-$sha after $mins minutes." >&2
          local pn=
          [[ -n ${pfile_hint:-} ]] && { pn=$(pipeline_name "$pfile_hint") || true; }
          if [[ -n $pn ]]; then
            local extra
            extra=$(check_run_hint "$sha" "$pn") || true
            [[ -n ${extra:-} ]] && echo "$extra" >&2
          fi
          exit 1
          ;;
      esac
    fi

    # Check whether the PR changes the component's sources.
    local pfile_pr list_pr hit status_cm=0
    local -a patterns_pr
    pfile_pr=$(tekton_pipeline "$component" pull-request) || exit 1
    list_pr=$(tekton_patterns "$pfile_pr") || exit 1
    mapfile -t patterns_pr <<<"$list_pr"
    hit=$(changed_match "$base_sha" "$sha" "${patterns_pr[@]}") || status_cm=$?
    case $status_cm in
      0)
        # PR changes the sources. Wait for the build to start.
        local pn image elapsed=0
        pn=$(pipeline_name "$pfile_pr") || true
        image="$repo/$component:on-pr-$sha"
        echo "This PR changes ${hit%% (*}, so it needs $image" >&2
        while (( elapsed < wait_seconds )); do
          if has "$component" "on-pr-$sha.git"; then
            local ws2=0
            wait_for_tag "$component" "on-pr-$sha" || ws2=$?
            case $ws2 in
              0) echo "$image"; return ;;
              1)
                echo "$image has expired. Comment \"/test ${pn:-$component-on-pull-request}\" to rebuild it, then /retest." >&2
                exit 1
                ;;
              2)
                echo "Konflux hasn't finished building $image after $((wait_seconds / 60)) minutes." >&2
                if [[ -n $pn ]]; then
                  local extra2
                  extra2=$(check_run_hint "$sha" "$pn") || true
                  [[ -n ${extra2:-} ]] && echo "$extra2" >&2
                fi
                exit 1
                ;;
            esac
          fi
          sleep 30
          elapsed=$((elapsed + 30))
        done
        # Build was never started.
        local file=${hit%% (*}
        echo "This PR changes $file, so it must be tested with $image, but Konflux hasn't started that build. Comment \"/test ${pn:-$component-on-pull-request}\" on the PR to build it, then /retest." >&2
        exit 1
        ;;
      1) ;; # No match — fall through to base build.
      *)
        exit 1
        ;;
    esac
  fi

  # -- Base build: find the newest base commit that changes the sources --

  if [[ -n $base_sha ]]; then
    if ! git cat-file -e "$base_sha^{commit}" 2>/dev/null; then
      echo "The checkout lacks commit $base_sha (the base). A full clone is needed for --strict" >&2
      exit 1
    fi
    local pfile_push list_push commit status_lmc=0
    local -a patterns_push
    pfile_push=$(tekton_pipeline "$component" push) || exit 1
    list_push=$(tekton_patterns "$pfile_push") || exit 1
    mapfile -t patterns_push <<<"$list_push"
    commit=$(last_matching_commit "$base_sha" "${patterns_push[@]}") || status_lmc=$?
    case $status_lmc in
      0) ;;
      1)
        echo "None of the newest 500 commits of $base_sha changes $component's sources" >&2
        exit 1
        ;;
      *)
        exit 1
        ;;
    esac
    local image="$repo/$component:$commit"
    echo "Testing with the build of $commit, the newest commit of $base_sha that changes $component's sources" >&2
    # Check if the image is already active.
    if has "$component" "$commit" active; then
      echo "$image"
      return
    fi
    # Check if the build is in progress.
    if has "$component" "$commit.git"; then
      local ws3=0
      wait_for_tag "$component" "$commit" || ws3=$?
      case $ws3 in
        0) echo "$image"; return ;;
        1|2)
          if (( ws3 == 2 )); then
            echo "Konflux hasn't finished building $image after $((wait_seconds / 60)) minutes." >&2
            local pn3
            pn3=$(pipeline_name "$pfile_push") || true
            if [[ -n $pn3 ]]; then
              local extra3
              extra3=$(check_run_hint "$commit" "$pn3") || true
              [[ -n ${extra3:-} ]] && echo "$extra3" >&2
            fi
          else
            echo "$image, the build of base commit $commit (the newest that changes $component's sources), doesn't exist; its Konflux push build may have failed." >&2
          fi
          exit 1
          ;;
      esac
    fi
    # No build at all.
    echo "$image, the build of base commit $commit (the newest that changes $component's sources), doesn't exist; its Konflux push build may have failed." >&2
    exit 1
  fi

  # -- No base SHA and no git checkout: local run outside the repository --

  if has "$component" "$tag" active; then
    echo "No git history available; using the branch tag $repo/$component:$tag" >&2
    echo "$repo/$component:$tag"
    return
  fi
  echo "$repo/$component:$tag doesn't exist. Set KONFLUX_TAG, or check the Konflux push builds for $tag." >&2
  exit 1
}

# ---- Main loop ----

for component; do
  if [[ -n $strict ]]; then
    resolve_strict "$component"
  else
    resolve "$component"
  fi
done
