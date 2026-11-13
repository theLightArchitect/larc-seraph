#!/usr/bin/env bash
# Fail when a non-merge commit on this branch is missing a Signed-off-by trailer.
# Usage: tools/check_dco.sh [base-ref]
# base-ref defaults to origin/main. Merge commits are skipped.

set -euo pipefail

base="${1:-origin/main}"

if ! git rev-parse --verify "${base}^{commit}" >/dev/null 2>&1; then
  echo "base ref not available: ${base}" >&2
  exit 1
fi

missing=0
while read -r sha; do
  [ -z "${sha}" ] && continue
  # A second parent means a merge commit. GitHub's merge button does not add a trailer.
  if git rev-parse --verify "${sha}^2" >/dev/null 2>&1; then
    continue
  fi
  if ! git log -1 --format=%B "${sha}" | grep -q '^Signed-off-by: '; then
    echo "missing Signed-off-by: $(git log -1 --format='%h %s' "${sha}")" >&2
    missing=1
  fi
done < <(git rev-list "${base}..HEAD")

exit "${missing}"
