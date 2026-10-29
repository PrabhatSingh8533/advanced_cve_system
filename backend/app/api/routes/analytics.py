"""Analytics API - All endpoints use real DB data."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from loguru import logger
from app.db.session import get_db

router = APIRouter(
    prefix="/api/analytics", tags=["Temporal Analytics"]
)

_service = None


def get_service():
    global _service
    if _service is None:
        from app.services.analytics.analyzer import (
            CVEAnalyticsService
        )
        _service = CVEAnalyticsService()
        logger.info("Analytics service initialized")
    return _service


@router.get("/overview")
def get_overview(db: Session = Depends(get_db)):
    return get_service().get_overview(db=db)


@router.get("/charts/monthly")
def monthly_chart(db: Session = Depends(get_db)):
    return get_service().get_monthly_chart(db=db)


@router.get("/charts/severity")
def severity_chart(db: Session = Depends(get_db)):
    return get_service().get_severity_chart(db=db)


@router.get("/rce")
def rce_analysis():
    return get_service().get_rce_analysis()


@router.get("/os")
def os_analysis():
    return get_service().get_os_analysis()


@router.get("/forecast")
def forecast(
    steps: int = Query(
        default=12, ge=1, le=24,
        description="Months to forecast (1-24)"
    ),
    db: Session = Depends(get_db)
):
    """
    Forecast CVE counts using real DB data + ARIMA.
    Uses actual monthly CVE publication counts.
    """
    return get_service().get_forecast(steps=steps, db=db)


@router.get("/heatmap")
def exploit_heatmap():
    return get_service().get_exploit_heatmap()


@router.get("/summary")
def get_summary(db: Session = Depends(get_db)):
    return get_service().get_summary(db=db)


@router.get("/current-coverage")
def current_coverage():
    """Show data coverage info."""
    from datetime import datetime
    now = datetime.now()
    return {
        "current_date": now.strftime("%Y-%m-%d"),
        "current_year": now.year,
        "current_month": now.strftime("%B %Y"),
        "years_covered": list(range(2015, now.year + 1)),
        "note": f"Data through {now.strftime('%B %Y')}"
    }
