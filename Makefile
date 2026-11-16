# Run from WSL2 Ubuntu or the dev container (see docs/setup.md).
# F3 adds up, down, secrets and replay.
.PHONY: lint test

lint:
	pre-commit run --all-files

test:
	python3 -m pytest -q
