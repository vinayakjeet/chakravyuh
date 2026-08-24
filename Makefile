.PHONY: bench test lint conventions matrix

bench:
	uv run python scripts/status.py

matrix:
	uv run python scripts/matrix.py

test:
	uv run pytest

lint:
	uv run ruff check .

conventions:
	uv run python scripts/check_conventions.py
