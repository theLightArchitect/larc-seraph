## What changed

<!-- One short paragraph. Say whether detection logic changed. -->

## Checklist

- [ ] Detection logic is unchanged, or the changelog and the evasion notes say what the match change is.
- [ ] YARA metadata includes author, date, modified, description, reference, id, version, `attack_technique`, and `attack_tactic`.
- [ ] Sigma metadata includes id, status, level, tags, logsource, and falsepositives.
- [ ] New or changed rules have at least one positive fixture and one negative fixture. Positives match only that rule. Negatives and `known_good` match nothing. Fixtures are synthetic and contain `synthetic-benign`.
- [ ] `pytest` passes, including `yarac --fail-on-warnings` and `yr compile`.
- [ ] `sigma check --fail-on-issues --exclude d3_fendtag rules/sigma` passes when Sigma rules changed.
- [ ] `python tools/check_rule_metadata.py` passes.
- [ ] `CHANGELOG.md` has an entry when the user-facing pack changes.
- [ ] Commits on this branch have a `Signed-off-by` trailer (`git commit -s`).
- [ ] No credentials, tokens, or private paths.

## How tested

<!-- Commands you ran, and anything you could not run. -->
