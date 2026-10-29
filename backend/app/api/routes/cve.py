"""
CVE Search and Filter API - Public Access.

All endpoints are publicly accessible.
No authentication required.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, func, desc, and_
from typing import Optional
from loguru import logger

from app.db.session import get_db
from app.db.models.cve import CVE
from app.db.models.cwe import CWE

router = APIRouter(prefix="/api/cves", tags=["CVE Database"])


def cve_to_dict(cve: CVE) -> dict:
    """Convert CVE model to response dict."""
    return {
        "id": cve.id,
        "cve_id": cve.cve_id,
        "description": cve.description,
        "published_date": str(cve.published_date)
            if cve.published_date else None,
        "cvss_score": cve.cvss_score,
        "severity": cve.severity,
        "exploit_type": cve.exploit_type,
        "cwe_code": cve.cwe.cwe_code if cve.cwe else None,
        "cwe_name": cve.cwe.name if cve.cwe else None,
    }


@router.get("/")
def list_cves(
    severity: Optional[str] = Query(
        None,
        description="CRITICAL / HIGH / MEDIUM / LOW"
    ),
    exploit_type: Optional[str] = Query(
        None, description="Filter by exploit type"
    ),
    min_cvss: Optional[float] = Query(
        None, ge=0.0, le=10.0
    ),
    max_cvss: Optional[float] = Query(
        None, ge=0.0, le=10.0
    ),
    year: Optional[int] = Query(None),
    cwe: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """List CVEs with optional filters and pagination."""
    query = db.query(CVE).options(joinedload(CVE.cwe))

    if severity:
        query = query.filter(CVE.severity == severity.upper())

    if exploit_type:
        query = query.filter(
            CVE.exploit_type.ilike(f"%{exploit_type}%")
        )

    if min_cvss is not None:
        query = query.filter(CVE.cvss_score >= min_cvss)

    if max_cvss is not None:
        query = query.filter(CVE.cvss_score <= max_cvss)

    if year:
        query = query.filter(
            func.extract("year", CVE.published_date) == year
        )

    if cwe:
        query = query.join(CWE).filter(
            CWE.cwe_code.ilike(f"%{cwe}%")
        )

    total = query.count()
    offset = (page - 1) * page_size
    cves = query.order_by(
        desc(CVE.cvss_score)
    ).offset(offset).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "items": [cve_to_dict(c) for c in cves]
    }


@router.get("/search")
def search_cves(
    q: str = Query(..., min_length=2),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Full-text search across CVE IDs and descriptions."""
    search_term = f"%{q}%"

    query = db.query(CVE).options(
        joinedload(CVE.cwe)
    ).filter(
        or_(
            CVE.cve_id.ilike(search_term),
            CVE.description.ilike(search_term),
            CVE.exploit_type.ilike(search_term)
        )
    )

    total = query.count()
    offset = (page - 1) * page_size

    cves = query.order_by(
        desc(CVE.cvss_score)
    ).offset(offset).limit(page_size).all()

    return {
        "query": q,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "items": [cve_to_dict(c) for c in cves]
    }


@router.get("/stats")
def get_cve_stats(db: Session = Depends(get_db)):
    """Get CVE database statistics."""
    total = db.query(CVE).count()

    if total == 0:
        return {
            "total_cves": 0,
            "message": "No CVEs in database yet.",
            "hint": "POST /api/collect/recent?days=30"
        }

    # Severity distribution
    severity_counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_counts[sev] = db.query(CVE).filter(
            CVE.severity == sev
        ).count()

    # Top exploit types
    exploit_counts = db.query(
        CVE.exploit_type,
        func.count(CVE.id).label("count")
    ).filter(
        CVE.exploit_type.isnot(None)
    ).group_by(CVE.exploit_type).order_by(
        desc("count")
    ).limit(10).all()

    # Top CWEs
    top_cwes = db.query(
        CWE.cwe_code,
        CWE.name,
        func.count(CVE.id).label("count")
    ).join(CVE).group_by(
        CWE.cwe_code, CWE.name
    ).order_by(desc("count")).limit(10).all()

    # Average CVSS
    avg_cvss = db.query(
        func.avg(CVE.cvss_score)
    ).filter(CVE.cvss_score.isnot(None)).scalar()

    # CVSS distribution
    cvss_dist = {
        "critical_9_10": db.query(CVE).filter(
            CVE.cvss_score >= 9.0
        ).count(),
        "high_7_9": db.query(CVE).filter(
            and_(CVE.cvss_score >= 7.0, CVE.cvss_score < 9.0)
        ).count(),
        "medium_4_7": db.query(CVE).filter(
            and_(CVE.cvss_score >= 4.0, CVE.cvss_score < 7.0)
        ).count(),
        "low_0_4": db.query(CVE).filter(
            CVE.cvss_score < 4.0
        ).count(),
    }

    return {
        "total_cves": total,
        "average_cvss_score": round(float(avg_cvss or 0), 2),
        "severity_distribution": severity_counts,
        "cvss_distribution": cvss_dist,
        "top_exploit_types": [
            {"type": r.exploit_type, "count": r.count}
            for r in exploit_counts
        ],
        "top_cwes": [
            {
                "cwe_code": r.cwe_code,
                "name": r.name,
                "count": r.count
            }
            for r in top_cwes
        ]
    }


@router.get("/recent")
def get_recent_cves(
    days: int = Query(7, ge=1, le=365),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get CVEs published in the last N days."""
    from datetime import date, timedelta
    cutoff = date.today() - timedelta(days=days)

    cves = db.query(CVE).options(
        joinedload(CVE.cwe)
    ).filter(
        CVE.published_date >= cutoff
    ).order_by(
        desc(CVE.published_date),
        desc(CVE.cvss_score)
    ).limit(limit).all()

    return {
        "days": days,
        "count": len(cves),
        "items": [cve_to_dict(c) for c in cves]
    }


@router.get("/critical")
def get_critical_cves(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get highest severity CVEs (CVSS >= 9.0)."""
    cves = db.query(CVE).options(
        joinedload(CVE.cwe)
    ).filter(
        CVE.cvss_score >= 9.0
    ).order_by(
        desc(CVE.cvss_score),
        desc(CVE.published_date)
    ).limit(limit).all()

    return {
        "count": len(cves),
        "threshold": "CVSS >= 9.0",
        "items": [cve_to_dict(c) for c in cves]
    }


@router.get("/{cve_id}")
def get_cve(
    cve_id: str,
    db: Session = Depends(get_db)
):
    """Get single CVE by ID. Example: /api/cves/CVE-2021-44228"""
    cve = db.query(CVE).options(
        joinedload(CVE.cwe)
    ).filter(
        CVE.cve_id == cve_id.upper()
    ).first()

    if not cve:
        raise HTTPException(
            status_code=404,
            detail=f"CVE '{cve_id}' not found"
        )

    return cve_to_dict(cve)


@router.post("/analyze")
def analyze_cve_text(
    text: str = Query(..., min_length=10),
    db: Session = Depends(get_db)
):
    """Complete analysis of CVE description text."""
    result = {"input_text": text[:200]}

    # NLP Analysis
    try:
        from app.services.nlp.pipeline import CVENLPPipeline
        pipeline = CVENLPPipeline()
        nlp = pipeline.process(text)
        result["nlp"] = {
            "entities": nlp.get("entities", {}),
            "key_phrases": nlp.get(
                "dependency_parse", {}
            ).get("key_phrases", []),
            "tokens": nlp.get("tokens", [])[:20]
        }
    except Exception as e:
        result["nlp"] = {"error": str(e)}

    # BERT Exploit Prediction
    try:
        from app.services.ml.bert_inference import CVEBERTInference
        bert = CVEBERTInference.get_instance()
        if bert.is_model_trained():
            result["exploit_prediction"] = bert.predict(text)
        else:
            result["exploit_prediction"] = {
                "note": "Train BERT first: POST /api/bert/train"
            }
    except Exception as e:
        result["exploit_prediction"] = {"error": str(e)}

    # Severity Prediction
    try:
        from app.services.ml.severity.predictor import (
            CVESSeverityPredictor
        )
        pred = CVESSeverityPredictor()
        if pred.is_trained():
            result["severity_prediction"] = (
                pred.predict_ensemble(text)
            )
        else:
            result["severity_prediction"] = {
                "note": "Train severity: POST /api/severity/train"
            }
    except Exception as e:
        result["severity_prediction"] = {"error": str(e)}

    return result
