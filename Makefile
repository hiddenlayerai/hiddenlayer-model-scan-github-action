.PHONY: tests

install:
	uv pip install -r requirements.txt

install-dev:
	uv pip install -r requirements-dev.txt

install-uv:
	brew install uv

tests:
	.venv/bin/python -m pytest -sv tests/

venv:
	uv venv

lint:
	.venv/bin/python -m ruff check .

format:
	.venv/bin/python -m ruff format .
