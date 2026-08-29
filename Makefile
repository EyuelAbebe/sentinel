.PHONY: help install lint typecheck test run scan smoke fmt clean bump-patch bump-minor bump-major

# Marker file tracks last successful install. Deleted automatically when .venv is cleaned.
INSTALLED_MARKER := .venv/.installed

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

# Guard: runs install if marker is missing OR sentinel is not importable in the venv.
_ensure-installed:
	@if [ ! -f $(INSTALLED_MARKER) ] || ! poetry run python -c "import sentinel" 2>/dev/null; then \
		$(MAKE) --no-print-directory _do-install; \
	fi

_do-install:
	poetry config virtualenvs.in-project true
	poetry env remove --all 2>/dev/null || true
	poetry install --all-extras
	@touch $(INSTALLED_MARKER)

install: _do-install

run: _ensure-installed
	poetry run sentinel

scan: _ensure-installed
	poetry run sentinel scan

smoke: _ensure-installed
	@echo "==> lint"
	poetry run ruff check src/ tests/
	poetry run ruff format --check src/ tests/
	@echo "==> tests"
	poetry run pytest tests/ -q
	@echo "==> sentinel scan"
	poetry run sentinel scan
	@echo "==> all checks passed"

lint:
	poetry run ruff check src/ tests/
	poetry run ruff format --check src/ tests/

fmt:
	poetry run ruff format src/ tests/
	poetry run ruff check --fix src/ tests/

typecheck:
	poetry run mypy src/

test:
	poetry run pytest tests/ -v

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
