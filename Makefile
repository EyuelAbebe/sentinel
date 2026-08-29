.PHONY: install lint typecheck test run clean bump-patch bump-minor bump-major

install:
	poetry install

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

run:
	poetry run sentinel

bump-patch:
	poetry version patch

bump-minor:
	poetry version minor

bump-major:
	poetry version major

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov dist
