"""Advanced CVE Analysis System - Local Version."""

import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from app.db.base import Base
from app.db.session import engine
from app.db.models.cve import CVE
from app.db.models.cwe import CWE

Base.metadata.create_all(bind=engine)
logger.info("Database tables ready")

# Import ALL routers
from app.api.routes.cve import router as cve_router
from app.api.routes.scraping import router as scraping_router
from app.api.routes.analytics import router as analytics_router
from app.api.routes.nlp import router as nlp_router
from app.api.routes.bert import router as bert_router
from app.api.routes.severity import router as severity_router

app = FastAPI(
    title="Advanced CVE Analysis System",
    version="1.0.0",
    docs_url="/docs"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def timing(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    ms = round((time.time() - start) * 1000, 2)
    response.headers["X-Process-Time"] = f"{ms}ms"
    return response


@app.exception_handler(Exception)
async def error_handler(request: Request, exc: Exception):
    logger.error(f"Error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": str(exc)}
    )


# Register ALL routers
app.include_router(cve_router)
app.include_router(scraping_router)
app.include_router(analytics_router)
app.include_router(nlp_router)
app.include_router(bert_router)
app.include_router(severity_router)


@app.get("/")
def root():
    return {
        "name": "Advanced CVE Analysis System",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
def health():
    from app.db.session import SessionLocal
    from sqlalchemy import text
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        count = db.query(CVE).count()
        return {
            "status": "healthy",
            "database": "connected",
            "cve_count": count
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}
    finally:
        db.close()


@app.get("/routes")
def list_routes():
    return {
        "routes": [
            {"path": r.path, "methods": list(r.methods)}
            for r in app.routes
            if hasattr(r, "methods")
        ]
    }
