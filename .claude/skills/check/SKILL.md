---
name: check
description: Run lint and tests, group failures by file, propose the smallest fix. Use before opening or updating a pull request.
---

1. Run `make lint` and `make test` from the repository root.
2. If both pass, say so in one line with the test count, and stop.
3. Group the failures by file. For each, quote the failing line or assertion.
4. Propose the smallest change that fixes each failure. Do not apply it without the student's confirmation.
5. Never fix a failure by editing `detector/thresholds.json`, `models/`, `tests/regression/` or the guard hook. If the fix needs one of those, say so and stop: the student changes them by hand.
6. If a gitleaks finding appears, do not print the matched value. Name the file and line, and point to the rotation runbook in `SECURITY.md`.
