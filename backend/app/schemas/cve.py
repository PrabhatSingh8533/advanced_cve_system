"""CVE Pydantic Schemas."""

from pydantic import BaseModel
from typing import Optional, List
from datetime import date


class CVESearchParams(BaseModel):
    """CVE search/filter parameters."""
    query: Optional[str] = None
    severity: Optional[str] = None
    min_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    exploit_type: Optional[str] = None
    year: Optional[int] = None
    cwe_id: Optional[str] = None


class CVEResponse(BaseModel):
    """Single CVE response schema."""
    id: int
    cve_id: str
    description: str
    published_date: Optional[date] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    exploit_type: Optional[str] = None
    cwe_code: Optional[str] = None

    class Config:
        from_attributes = True


class CVEListResponse(BaseModel):
    """Paginated CVE list response."""
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[CVEResponse]


class CVEStatsResponse(BaseModel):
    """CVE statistics response."""
    total_cves: int
    severity_distribution: dict
    exploit_type_distribution: dict
    top_cwe: List[dict]
    recent_count: int
