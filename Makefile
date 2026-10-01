# ============================================================
# Autonomous SecOps Agent -- Developer Makefile
# ============================================================
.PHONY: help dev-backend dev-frontend test eval docker-build docker-up docker-down lint

help:
	@echo "Available targets:"
	@echo "  dev-backend    -- Run FastAPI dev server"
	@echo "  dev-frontend   -- Run Vite dev server"
	@echo "  test           -- Run pytest suite"
	@echo "  eval           -- Run Phase 8 evaluation benchmark"
	@echo "  docker-build   -- Build Docker images"
	@echo "  docker-up      -- Start full stack via docker-compose"
	@echo "  docker-down    -- Stop and remove docker-compose stack"
	@echo "  lint           -- Run oxlint on frontend"

dev-backend:
	uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:
	cd frontend && npm run dev

test:
	pytest tests/ -v --tb=short

eval:
	python -m backend.evaluation.runner

docker-build:
	docker build -t secops-backend:latest ./backend
	docker build -t secops-frontend:latest ./frontend

docker-up:
	docker compose -f infra/docker-compose.yml up -d --build

docker-down:
	docker compose -f infra/docker-compose.yml down -v

lint:
	cd frontend && npm run lint
