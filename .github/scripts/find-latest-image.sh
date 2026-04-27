#!/usr/bin/env bash
set -euo pipefail

# Searches backwards through GitHub releases to find the newest release
# where all specified container images have been published.
#
# Usage: find-latest-image.sh <github_repo> <image1> [image2 ...]
#   github_repo: GitHub repo in "owner/name" format
#   image1..N:   Full image references without tags (e.g., ghcr.io/org/name)
#
# Options (via environment variables):
#   SEMVER_ONLY=true    Skip non-semver tags (default: false)
#   FALLBACK_TAG=<tag>  Tag to return if no release has published images (default: exits 1)
#
# Outputs the matched tag to stdout. All logging goes to stderr.

GITHUB_REPO="$1"
shift
IMAGES=("$@")

if [ ${#IMAGES[@]} -eq 0 ]; then
  echo "Usage: find-latest-image.sh <github_repo> <image1> [image2 ...]" >&2
  exit 1
fi

SEMVER_ONLY="${SEMVER_ONLY:-false}"
FALLBACK_TAG="${FALLBACK_TAG:-}"

RELEASES=$(curl -sf --retry 3 --retry-delay 5 \
  "https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=20" \
  | jq -r '.[].tag_name')

for RELEASE_TAG in $RELEASES; do
  if [ "$SEMVER_ONLY" = "true" ]; then
    if ! echo "$RELEASE_TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+'; then
      echo "Skipping non-semver tag: $RELEASE_TAG" >&2
      continue
    fi
  fi

  echo "Checking images for ${GITHUB_REPO} release ${RELEASE_TAG}..." >&2
  ALL_FOUND=true
  for IMAGE in "${IMAGES[@]}"; do
    if ! skopeo inspect --override-arch amd64 --override-os linux \
      "docker://${IMAGE}:${RELEASE_TAG}" > /dev/null 2>&1; then
      ALL_FOUND=false
      break
    fi
  done

  if [ "$ALL_FOUND" = "true" ]; then
    echo "Found images for ${GITHUB_REPO} release ${RELEASE_TAG}" >&2
    echo "$RELEASE_TAG"
    exit 0
  else
    echo "Images not found for ${RELEASE_TAG}, trying next..." >&2
  fi
done

if [ -n "$FALLBACK_TAG" ]; then
  echo "No versioned images found, using fallback: ${FALLBACK_TAG}" >&2
  echo "$FALLBACK_TAG"
  exit 0
fi

echo "No release with published images found for ${GITHUB_REPO}" >&2
exit 1
