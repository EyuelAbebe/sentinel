.PHONY: help install lint typecheck test run scan smoke fmt clean bump-patch bump-minor bump-major

# Always use the venv directly — avoids `poetry run` triggering broken-venv detection on every call.
PYTHON  := .venv/bin/python
SENTINEL := .venv/bin/sentinel
PYTEST  := .venv/bin/pytest
RUFF    := .venv/bin/ruff
MYPY    := .venv/bin/mypy

export POETRY_VIRTUALENVS_IN_PROJECT := true
export POETRY_VIRTUALENVS_CREATE     := true

help:
	@echo ""
	@echo "  Setup"
	@echo "    make install      Install all dependencies (run once after clone or after pulling)"
	@echo ""
	@echo "  Daily use"
	@echo "    make run          Launch the interactive TUI"
	@echo "    make scan         Run a quick one-shot security scan"
	@echo "    make test         Run the test suite"
	@echo "    make fmt          Auto-fix formatting and lint"
	@echo "    make lint         Check code style (read-only)"
	@echo "    make typecheck    Run mypy strict type checking"
	@echo ""
	@echo "  Pre-PR"
	@echo "    make smoke        Full local check: lint + test + sentinel scan"
	@echo ""
	@echo "  Release"
	@echo "    make bump-patch / bump-minor / bump-major"
	@echo ""

# Build target: recreates .venv and installs when pyproject.toml or poetry.lock change.
$(PYTHON): pyproject.toml poetry.lock
	poetry env remove --all 2>/dev/null || true
	poetry install --all-extras
	@touch $(PYTHON)

install: $(PYTHON)

run: $(PYTHON)
	$(SENTINEL)

scan: $(PYTHON)
	$(SENTINEL) scan

smoke: $(PYTHON)
	@echo "==> lint"
	$(RUFF) check src/ tests/
	$(RUFF) format --check src/ tests/
	@echo "==> tests"
	$(PYTEST) tests/ -q
	@echo "==> sentinel scan"
	$(SENTINEL) scan
	@echo "==> all checks passed"

lint:
	$(RUFF) check src/ tests/
	$(RUFF) format --check src/ tests/

fmt:
	$(RUFF) format src/ tests/
	$(RUFF) check --fix src/ tests/

typecheck:
	$(MYPY) src/

test:
	$(PYTEST) tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov dist .venv

bump-patch:
	poetry version patch

bump-minor:
	poetry version minor

bump-major:
	poetry version major
