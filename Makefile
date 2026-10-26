UV ?= uv
PYTHON ?= 3.11

.PHONY: help sync develop check lint test build clean

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-12s %s\n", $$1, $$2}'

sync: ## Install dev tools into .venv
	$(UV) sync --group dev

develop: ## Build the extension into the project venv
	$(UV) run maturin develop --uv --release

check: lint test ## Lint and test

lint: ## Ruff on Python sources
	$(UV) run ruff check tests
	$(UV) run ruff format --check tests

test: develop ## Run pytest against the built extension
	$(UV) run pytest

build: ## Build release wheels into dist/
	mkdir -p dist
	$(UV) run maturin build --release --out dist

clean: ## Remove build artefacts
	rm -rf dist target/wheels .pytest_cache .ruff_cache
