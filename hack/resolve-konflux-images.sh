#!/bin/bash
# resolve-konflux-images.sh — Resolve Konflux-built images for e2e testing.
#
# Source this file before running e2e tests in CI:
#   source hack/resolve-konflux-images.sh
#   make e2e-parallel
#
# Konflux builds PR images while the cluster installs, so test with them
# instead of having Prow build them before the install starts. Konflux builds
# an image only for PRs that change its sources; other PRs test with the
# master image, which has the same sources.
#
# See also DEFAULT_KONFLUX_REPO and DEFAULT_KONFLUX_TAG in the Makefile.

set -euo pipefail

KONFLUX_REPO="${KONFLUX_REPO:-redhat-user-workloads/ocp-isc-tenant}"

# has <image> <tag> [active] — whether Quay has the tag (or ever had it).
has() {
  local out
  out=$(curl -fsS --max-time 30 --retry 5 --retry-all-errors \
    "https://quay.io/api/v1/repository/${KONFLUX_REPO}/$1/tag/?specificTag=$2${3:+&onlyActiveTags=true}") || return 1
  [[ $out == *'"name"'* ]]
}

# konflux <image> — resolve the Konflux build of an image to test with.
konflux() {
  local tag="on-pr-${PULL_PULL_SHA:-}" delay
  # A Konflux build stores its source commit at <tag>.git when it starts.
  if [[ -n ${PULL_PULL_SHA:-} ]] && has "$1" "$tag.git"; then
    # Retry with backoff for up to 5 minutes while the build finishes.
    for delay in 10 20 40 80 150 0; do
      has "$1" "$tag" active && { echo "quay.io/${KONFLUX_REPO}/$1:$tag"; return; }
      has "$1" "$tag.git" active || { echo "quay.io/${KONFLUX_REPO}/$1:$tag has expired: /test $1-on-pull-request rebuilds it" >&2; return 1; }
      sleep "$delay"
    done
    echo "Konflux has not built quay.io/${KONFLUX_REPO}/$1:$tag after 5 minutes" >&2
    return 1
  fi
  echo "quay.io/${KONFLUX_REPO}/$1:master"
}

IMAGE_FROM_CI=$(konflux compliance-operator-dev)
OPENSCAP_IMAGE=$(konflux compliance-operator-openscap-dev)
MUST_GATHER_IMAGE=$(konflux compliance-operator-must-gather-dev)
export IMAGE_FROM_CI OPENSCAP_IMAGE MUST_GATHER_IMAGE

echo "Testing with IMAGE_FROM_CI=$IMAGE_FROM_CI OPENSCAP_IMAGE=$OPENSCAP_IMAGE MUST_GATHER_IMAGE=$MUST_GATHER_IMAGE"
