.DEFAULT_GOAL := default
LINT_TARGETS := deleting_messages_tool.py

.PHONY: default
default: tools lint

.PHONY: tools
tools:
	pip3 install poetry==1.8.3
	poetry install

.PHONY: lint
lint:
	poetry run black $(LINT_TARGETS)
	poetry run isort --profile black $(LINT_TARGETS)
	poetry run flake8 --extend-ignore E203 --max-line-length 100 $(LINT_TARGETS)
	poetry run mypy --scripts-are-modules $(LINT_TARGETS)
