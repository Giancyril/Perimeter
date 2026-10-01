from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.api.health import router as health_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.incidents import router as incidents_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-seed benchmark scenarios in development if engine is empty
    if settings.ENVIRONMENT == "development":
        try:
            from backend.correlation.engine import correlation_engine
            if not correlation_engine.list_incidents():
                from backend.evaluation.dataset import BENCHMARK_SCENARIOS
                from backend.ingestion.engine import ingestion_engine
                for scenario in BENCHMARK_SCENARIOS:
                    for alert in scenario.alerts:
                        ingestion_engine.ingest(alert)
                print(f"[Startup] Auto-seeded {len(BENCHMARK_SCENARIOS)} demo scenarios into SecOps engine.")
        except Exception as e:
            print(f"[Startup] Note: Demo seeding skipped: {e}")
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous Security Operations Agent: Ingest SIEM alerts, correlate entities, investigate threats with LangGraph, score severity, and escalate with human approval.",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(health_router, tags=["health"])
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(incidents_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["root"])
async def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "docs_url": "/docs",
        "health_check": "/health",
        "version": settings.VERSION,
    }
