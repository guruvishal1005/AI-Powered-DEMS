SHELL := /bin/bash
VENV  := backend/.venv
PY    := $(VENV)/bin/python
PIP   := $(VENV)/bin/pip
BE    := cd backend &&
FE    := cd frontend &&

.DEFAULT_GOAL := help
.PHONY: help setup install-backend install-frontend db-up db-down db-logs db-shell \
        migrate migration reset-db seed api web dev test test-backend test-frontend \
        lint format typecheck check clean

help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

setup: install-backend install-frontend db-up migrate seed ## Full first-time setup
	@echo ""
	@echo "CYBERTRACE is ready. Run 'make api' and 'make web' in separate terminals."

install-backend: ## Create the venv and install backend dependencies
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements-dev.txt

install-frontend: ## Install frontend dependencies
	$(FE) pnpm install

db-up: ## Start PostgreSQL 18
	cd ops && docker compose up -d
	@echo "waiting for postgres..."
	@until docker exec cybertrace-db pg_isready -U cybertrace -d cybertrace >/dev/null 2>&1; \
	  do sleep 1; done; echo "postgres ready on localhost:5433"

db-down: ## Stop PostgreSQL (data is preserved)
	cd ops && docker compose down

db-logs: ## Tail database logs
	cd ops && docker compose logs -f db

db-shell: ## Open a psql shell
	docker exec -it cybertrace-db psql -U cybertrace -d cybertrace

migrate: ## Apply all database migrations
	$(BE) ../$(PY) -m alembic upgrade head

migration: ## Autogenerate a migration: make migration m="add x"
	$(BE) ../$(PY) -m alembic revision --autogenerate -m "$(m)"

reset-db: ## Drop and rebuild the database, then reseed (destroys all data)
	cd ops && docker compose down -v && docker compose up -d
	@until docker exec cybertrace-db pg_isready -U cybertrace -d cybertrace >/dev/null 2>&1; \
	  do sleep 1; done
	$(MAKE) migrate seed

seed: ## Generate demo evidence files and ingest them through the real pipeline
	$(BE) ../$(PY) -m app.seed.run

api: ## Run the API with reload on :8000
	$(BE) ../$(PY) -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

web: ## Run the frontend dev server on :5173
	$(FE) pnpm dev

test: test-backend test-frontend ## Run all tests

test-backend: ## Run backend tests
	$(BE) ../$(PY) -m pytest -q

test-frontend: ## Run frontend tests
	$(FE) pnpm test --run

lint: ## Lint backend and frontend
	$(BE) ../$(VENV)/bin/ruff check .
	$(FE) pnpm lint

format: ## Auto-format and auto-fix
	$(BE) ../$(VENV)/bin/ruff format . && ../$(VENV)/bin/ruff check --fix .
	$(FE) pnpm format

typecheck: ## Static type checks
	$(BE) ../$(VENV)/bin/mypy app
	$(FE) pnpm typecheck

check: lint typecheck test ## Everything CI would run

clean: ## Remove caches and build output
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf backend/.pytest_cache backend/.mypy_cache backend/.ruff_cache frontend/dist
