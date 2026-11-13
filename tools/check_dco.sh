#!/usr/bin/env bash
# Fail when a non-merge commit on this branch has no sign-off from a person.
# Usage: tools/check_dco.sh [base-ref]
# base-ref defaults to origin/main. Merge commits are skipped.
#
# A Signed-off-by certifies that a person has the right to submit the change.
# A coding agent's own trailer does not. A commit whose only sign-off is an
# agent identity passes when a later commit in the same range carries a DCO
# remediation line for its full sha, in the format the DCO GitHub app reads:
#   On behalf of <Author> <email>, I, <Name> <email>, hereby add my Signed-off-by to this commit: <sha>
#   I, <Name> <email>, hereby add my Signed-off-by to this commit: <sha>
# .github/dco.yml enables the same two forms for that app.

set -euo pipefail

base="${1:-origin/main}"
# Sign-off addresses that belong to coding agents, not to people.
agent_emails='^(cursoragent@cursor\.com|noreply@anthropic\.com|.*\[bot\]@users\.noreply\.github\.com)$'

if ! git rev-parse --verify "${base}^{commit}" >/dev/null 2>&1; then
  echo "base ref not available: ${base}" >&2
  exit 1
fi

# Full shas named by a remediation line anywhere in the range. grep exits 1 on
# no match, which is not an error here.
remediated="$(git log --format=%B "${base}..HEAD" \
  | grep -E -o 'hereby add my Signed-off-by to this commit: [0-9a-f]{40}' \
  | grep -E -o '[0-9a-f]{40}$' || true)"

missing=0
while read -r sha; do
  [ -z "${sha}" ] && continue
  # A second parent means a merge commit. GitHub's merge button does not add a trailer.
  if git rev-parse --verify "${sha}^2" >/dev/null 2>&1; then
    continue
  fi
  label="$(git log -1 --format='%h %s' "${sha}")"
  emails="$(git log -1 --format=%B "${sha}" \
    | sed -n 's/^Signed-off-by: .*<\(.*\)>[[:space:]]*$/\1/p')"
  if [ -z "${emails}" ]; then
    echo "missing Signed-off-by: ${label}" >&2
    missing=1
    continue
  fi
  person="$(printf '%s\n' "${emails}" | grep -E -v -i "${agent_emails}" || true)"
  if [ -n "${person}" ]; then
    continue
  fi
  if printf '%s\n' "${remediated}" | grep -q -x "${sha}"; then
    continue
  fi
  echo "only an agent signed off, and no remediation line names it: ${label}" >&2
  missing=1
done < <(git rev-list "${base}..HEAD")

exit "${missing}"
