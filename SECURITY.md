# Security policy

larc-seraph is defensive detection content. Report a vulnerability in private through [GitHub security advisories](https://github.com/theLightArchitect/larc-seraph/security/advisories/new). Do not open a public issue, pull request, or discussion for a security report.

Private vulnerability reporting has to be enabled in the repository settings before that page accepts a report from someone who is not a maintainer. If the page will not take a report, the setting is still off. Do not fall back to a public issue.

## In scope

- The scanner (`larc-seraph`) doing something other than printing matches: executing a scanned file, writing outside the paths it was asked to write, or sending the file or the match anywhere.
- A release archive, CI workflow, or dependency change that exposes credentials or runs untrusted code in this repository's workflows.
- A rule or fixture that is not detection content: an exploit, a live payload, or an instruction to attack a system.
- A packaging bug that drops the license or the author attribution the Detection Rule License requires.

## Out of scope

- A false positive or a false negative. Open a public issue. The evasion matrix in `validation/evasion-matrix.yml` lists misses that are already known.
- Detection bypasses that the README and `VALIDATION.md` already document.
- Whether a rule would be noisy on a fleet this project has not scanned.
- Vulnerabilities in YARA, yara-x, pySigma, Sigma, or an MCP server this pack only describes. Report those upstream.

## What to send

Name the version or commit, the file, and what an attacker gains. A synthetic fixture is enough. Do not include live credentials, a working exploit, or someone else's private data.

## Response

This is a single-maintainer project.

- Acknowledgement within 3 business days.
- A severity assessment within 10 business days of acknowledgement.
- A fix is developed in private. Critical issues in the scanner or in CI come before rule-quality work. There is no paid support and no guaranteed patch date.
- You choose whether the advisory credits you. The advisory is published when the fix is on `main`, or sooner if the issue is already public.
