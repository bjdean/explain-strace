.PHONY: help install install-dev test lint format clean build publish check

help:
	@echo "Available commands:"
	@echo "  make install      - Install package"
	@echo "  make install-dev  - Install package with dev dependencies"
	@echo "  make test         - Run tests"
	@echo "  make test-cov     - Run tests with coverage"
	@echo "  make lint         - Run linters (ruff)"
	@echo "  make format       - Format code (black, ruff)"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make build        - Build package"
	@echo "  make publish      - Publish to PyPI (requires credentials)"

install:
	pip install .

install-dev:
	pip install -e ".[dev]"

test:
	pytest

test-cov:
	pytest --cov=explain_strace --cov-report=html --cov-report=term

lint:
	ruff check src tests

format:
	black src tests
	ruff check --fix src tests

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

publish: build
	python -m twine upload dist/*

# Run all checks before committing
check: lint test
	@echo "All checks passed!"
