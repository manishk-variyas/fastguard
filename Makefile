.PHONY: install develop clean uninstall lint test help

install:
	uv pip install .

develop:
	uv pip install -e .

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

uninstall:
	uv pip uninstall fastguard -y

reinstall: uninstall clean install

lint:
	uv tool install ruff --quiet 2>/dev/null || true
	uv run ruff check .

fix:
	uv tool install ruff --quiet 2>/dev/null || true
	uv run ruff check --fix .

test:
	@echo "No tests found yet. Run 'uv tool install pytest && uv run pytest' to test."

help:
	@echo "FastGuard - Quick commands"
	@echo "  make install     - Install fastguard with uv"
	@echo "  make develop     - Install in editable mode"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make uninstall   - Remove fastguard"
	@echo "  make reinstall   - Full reinstall"
	@echo "  make lint        - Run ruff linter"
	@echo "  make fix         - Auto-fix lint issues"
	@echo "  make test        - Run tests"
