"""CVE Data Collection API."""

import time
from datetime import datetime, timedelta
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from loguru import logger
from app.db.session import SessionLocal

router = APIRouter(prefix="/api/collect", tags=["Data Collection"])

collection_status = {
    "is_running": False,
    "task": None,
    "started_at": None,
    "finished_at": None,
    "progress": {
        "fetched": 0, "parsed": 0,
        "saved": 0, "skipped": 0,
        "errors": 0, "total_in_db": 0,
    },
    "last_result": None,
    "error": None,
}


def run_collection_task(task_type: str, **kwargs):
    """Background collection task."""
    global collection_status

    collection_status["is_running"] = True
    collection_status["started_at"] = datetime.utcnow().isoformat()
    collection_status["error"] = None
    collection_status["progress"] = {
        "fetched": 0, "parsed": 0,
        "saved": 0, "skipped": 0,
        "errors": 0, "total_in_db": 0
    }

    db = SessionLocal()
    try:
        from app.services.scraping.nvd_client import NVDClient
        from app.services.scraping.nvd_parser import NVDParser
        from app.services.scraping.cleaner import CVECleaner
        from app.services.scraping.storage import CVEStorageService

        client = NVDClient()
        parser = NVDParser()
        cleaner = CVECleaner()
        storage = CVEStorageService(db)

        if task_type == "recent":
            days = kwargs.get("days", 7)
            logger.info(f"Collecting last {days} days...")
            raw_cves = client.fetch_recent_cves(days=days)

        elif task_type == "year":
            year = kwargs.get("year")
            logger.info(f"Collecting year {year}...")
            raw_cves = client.fetch_by_year(year)

        else:
            raise ValueError(f"Unknown task: {task_type}")

        collection_status["progress"]["fetched"] = len(raw_cves)

        if not raw_cves:
            collection_status["last_result"] = {
                "task": task_type,
                "fetched": 0,
                "saved": 0,
                "skipped": 0,
                "total_in_db": storage.get_total_count(),
                "note": "No new CVEs found"
            }
            return

        parsed = parser.parse_many(raw_cves)
        collection_status["progress"]["parsed"] = len(parsed)

        cleaned = cleaner.clean_many(parsed)
        summary = storage.save_many(cleaned)
        total = storage.get_total_count()

        collection_status["progress"].update({
            "saved": summary.get("saved", 0),
            "skipped": summary.get("skipped", 0),
            "errors": summary.get("errors", 0),
            "total_in_db": total,
        })

        collection_status["last_result"] = {
            "task": task_type,
            "fetched": len(raw_cves),
            "saved": summary.get("saved", 0),
            "skipped": summary.get("skipped", 0),
            "total_in_db": total,
        }

        logger.success(
            f"Done! Saved={summary.get('saved')} Total={total}"
        )

    except Exception as e:
        logger.error(f"Collection error: {e}", exc_info=True)
        collection_status["error"] = str(e)
    finally:
        db.close()
        collection_status["is_running"] = False
        collection_status["finished_at"] = datetime.utcnow().isoformat()


@router.get("/status")
def get_status():
    """Get collection status and DB stats."""
    from app.db.models.cve import CVE
    from app.db.models.cwe import CWE
    from sqlalchemy import func, extract

    db = SessionLocal()
    try:
        total = db.query(CVE).count()
        total_cwes = db.query(CWE).count()

        sev_counts = {
            s: db.query(CVE).filter(CVE.severity == s).count()
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        }

        date_range = db.query(
            func.min(CVE.published_date),
            func.max(CVE.published_date)
        ).first()

        year_dist = db.query(
            extract("year", CVE.published_date).label("year"),
            func.count(CVE.id).label("count")
        ).filter(
            CVE.published_date.isnot(None)
        ).group_by(
            extract("year", CVE.published_date)
        ).order_by(
            extract("year", CVE.published_date).desc()
        ).limit(15).all()

    finally:
        db.close()

    return {
        "database": {
            "total_cves": total,
            "total_cwes": total_cwes,
            "severity_distribution": sev_counts,
            "date_range": {
                "earliest": str(date_range[0]) if date_range[0] else None,
                "latest": str(date_range[1]) if date_range[1] else None,
            },
            "year_distribution": {
                str(int(r.year)): int(r.count)
                for r in year_dist if r.year
            }
        },
        "collection": {
            "is_running": collection_status["is_running"],
            "task": collection_status["task"],
            "started_at": collection_status["started_at"],
            "finished_at": collection_status["finished_at"],
            "progress": collection_status["progress"],
            "last_result": collection_status["last_result"],
            "error": collection_status["error"],
        }
    }


@router.get("/progress")
def get_progress():
    """Lightweight progress for polling."""
    return {
        "is_running": collection_status["is_running"],
        "task": collection_status["task"],
        "fetched": collection_status["progress"]["fetched"],
        "saved": collection_status["progress"]["saved"],
        "total_in_db": collection_status["progress"]["total_in_db"],
        "error": collection_status["error"],
        "finished_at": collection_status["finished_at"],
    }


@router.post("/recent")
def collect_recent(
    days: int = Query(7, ge=1, le=365),
    background_tasks: BackgroundTasks = None
):
    """Collect CVEs from last N days."""
    if collection_status["is_running"]:
        return {
            "message": "Already running",
            "status": "already_running",
            "progress": collection_status["progress"]
        }

    collection_status["task"] = f"recent_{days}_days"
    background_tasks.add_task(
        run_collection_task, "recent", days=days
    )

    return {
        "message": f"Started: collecting last {days} days",
        "status": "started",
        "tip": "Poll GET /api/collect/progress"
    }


@router.post("/year/{year}")
def collect_year(
    year: int,
    background_tasks: BackgroundTasks
):
    """Collect all CVEs for a year."""
    current_year = datetime.utcnow().year

    if year < 1999 or year > current_year:
        raise HTTPException(
            400,
            f"Year must be 1999-{current_year}"
        )

    if collection_status["is_running"]:
        return {
            "message": "Already running",
            "status": "already_running"
        }

    collection_status["task"] = f"year_{year}"
    background_tasks.add_task(
        run_collection_task, "year", year=year
    )

    return {
        "message": f"Started collecting {year}",
        "status": "started",
        "tip": "Poll GET /api/collect/progress"
    }
