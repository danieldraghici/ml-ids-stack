---
name: hooks-over-prose
description: a safety rule goes into the guard hook or a permission rule, not only into text
type: correction
---

When a rule protects a secret, the main branch, the threshold or the review process, enforce it in `.claude/hooks/guard.py` or in a permission rule in `.claude/settings.json`, with a test in `tests/test_hook.py`. A sentence in `CLAUDE.md` or in memory is not enough.

**Why:** memory and instructions are context the model can be talked out of (memory poisoning, R-05). The course requires at least one safety-critical rule enforced by a hook. The student edits the hook by hand; the hook blocks the agent from editing it.

**How to apply:** when you notice a rule that should be enforced, propose the hook change and its test in the pull request description. Do not edit the hook yourself.
