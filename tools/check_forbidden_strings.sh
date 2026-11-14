#!/usr/bin/env bash
# Fail if tracked text contains credential-shaped strings.
# This file is excluded: it has to name the strings in order to search for them.

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "${root}"

patterns=('ghp_' 'github_pat_' 'sk-' 'xox' 'AKIA' '-----BEGIN' 'ctx7' '/Users/kft')
failed=0

while IFS= read -r file; do
  [ "${file}" = "tools/check_forbidden_strings.sh" ] && continue
  [ -f "${file}" ] || continue
  for pattern in "${patterns[@]}"; do
    if grep -I -F -q -e "${pattern}" -- "${file}"; then
      echo "forbidden string ${pattern} in ${file}" >&2
      failed=1
    fi
  done
done < <(git ls-files)

exit "${failed}"
