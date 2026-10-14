#!/bin/bash
# resolve-konflux-images.sh — Print the Konflux builds of images to test with.
#
#   hack/resolve-konflux-images.sh <component>...
#
# For each Konflux component, such as compliance-operator-dev, this prints the
# pull spec of its build for the PR's head commit, waiting up to 30 minutes
# while Konflux finishes it. Konflux builds an image only for PRs that change
# its sources, so when it hasn't started a build for the PR, this prints the
# master build, which has the same sources. It fails rather than print another
# image when the PR's build has expired or doesn't finish in time, or when
# Quay can't be reached.
#
# CI jobs test with these images instead of having Prow build them before the
# cluster install starts:
#
#   IMAGE_FROM_CI=$(hack/resolve-konflux-images.sh compliance-operator-dev)
#   OPENSCAP_IMAGE=$(hack/resolve-konflux-images.sh compliance-operator-openscap-dev)
#
# Jobs for other repositories can run it from GitHub:
#
#   curl -fsSL https://raw.githubusercontent.com/ComplianceAsCode/compliance-operator/master/hack/resolve-konflux-images.sh |
#     bash -s -- compliance-operator-dev
#
# Environment:
#   KONFLUX_REPO  the Quay repository of the components (default:
#                 DEFAULT_KONFLUX_REPO in the Makefile)
#   KONFLUX_SHA   the commit to find the builds of (default: PULL_PULL_SHA,
#                 which Prow sets to the PR's head commit). Without one, the
#                 master builds are printed.

set -euo pipefail

repo=${KONFLUX_REPO:-quay.io/redhat-user-workloads/ocp-isc-tenant}
sha=${KONFLUX_SHA:-${PULL_PULL_SHA:-}}

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <component>..." >&2
  exit 2
fi
if [[ $repo != quay.io/* ]]; then
  echo "KONFLUX_REPO must be on quay.io: $repo" >&2
  exit 2
fi

# has <component> <tag> [active]: whether Quay has the tag, or ever had it.
# It exits when Quay can't be reached, so that an outage doesn't look like a
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

# resolve <component>: print the build of the component to test with.
resolve() {
  local tag=on-pr-$sha
  # A Konflux build stores its source at <tag>.git when it starts.
  if [[ -n $sha ]] && has "$1" "$tag.git"; then
    # Retry with backoff for up to 30 minutes while the build finishes.
    # ARM64 builds routinely take 15+ minutes, so budget generously.
    local elapsed=0 delay
    for delay in 10 20 40; do
      has "$1" "$tag" active && { echo "$repo/$1:$tag"; return; }
      has "$1" "$tag.git" active || {
        echo "$repo/$1:$tag has expired: /test $1-on-pull-request rebuilds it" >&2
        exit 1
      }
      sleep "$delay"
      elapsed=$((elapsed + delay))
    done
    while [[ $elapsed -lt 1800 ]]; do
      has "$1" "$tag" active && { echo "$repo/$1:$tag"; return; }
      has "$1" "$tag.git" active || {
        echo "$repo/$1:$tag has expired: /test $1-on-pull-request rebuilds it" >&2
        exit 1
      }
      sleep 60
      elapsed=$((elapsed + 60))
    done
    # Distinguish a slow build (PipelineRun still active) from a failed one.
    if has "$1" "$tag.git" active; then
      echo "Konflux is still building $repo/$1:$tag after 30 minutes; the PipelineRun may be unusually slow — check its status" >&2
    else
      echo "Konflux build of $repo/$1:$tag appears to have failed (PipelineRun finished without producing an image)" >&2
    fi
    exit 1
  fi
  echo "$repo/$1:master"
}

for component; do
  resolve "$component"
done
