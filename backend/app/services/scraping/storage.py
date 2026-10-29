"""
CVE Database Storage Service.
Handles saving cleaned CVE data to PostgreSQL.
"""

from datetime import date
from typing import Optional
from loguru import logger
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.db.models.cve import CVE
from app.db.models.cwe import CWE


class CVEStorageService:
    """
    Handles all database operations for CVE data.
    """

    def __init__(self, db: Session):
        """
        Initialize with database session.

        Args:
            db: SQLAlchemy database session
        """
        self.db = db

    def get_or_create_cwe(self, cwe_code: str) -> Optional[CWE]:
        """
        Get existing CWE or create new one.

        Args:
            cwe_code: CWE identifier (e.g., 'CWE-89')

        Returns:
            CWE database object
        """
        # Try to find existing
        cwe = self.db.query(CWE).filter(CWE.cwe_code == cwe_code).first()

        if not cwe:
            # Create new CWE entry
            cwe = CWE(
                cwe_code=cwe_code,
                name=self._get_cwe_name(cwe_code)
            )
            self.db.add(cwe)
            try:
                self.db.flush()  # Get ID without committing
            except IntegrityError:
                self.db.rollback()
                cwe = self.db.query(CWE).filter(
                    CWE.cwe_code == cwe_code
                ).first()

        return cwe

    def _get_cwe_name(self, cwe_code: str) -> str:
        """
        Return human-readable name for common CWEs.
        """
        cwe_names = {
            "CWE-79":  "Cross-site Scripting (XSS)",
            "CWE-89":  "SQL Injection",
            "CWE-20":  "Improper Input Validation",
            "CWE-125": "Out-of-bounds Read",
            "CWE-787": "Out-of-bounds Write",
            "CWE-200": "Information Exposure",
            "CWE-416": "Use After Free",
            "CWE-22":  "Path Traversal",
            "CWE-352": "Cross-Site Request Forgery",
            "CWE-434": "Unrestricted File Upload",
            "CWE-306": "Missing Authentication",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-94":  "Code Injection",
            "CWE-276": "Incorrect Default Permissions",
        }
        return cwe_names.get(cwe_code, f"Weakness {cwe_code}")

    def save_cve(self, cve_data: dict) -> Optional[CVE]:
        """
        Save a single cleaned CVE to the database.

        Args:
            cve_data: Cleaned CVE dictionary

        Returns:
            Saved CVE object or None if already exists
        """
        # Skip if CVE already exists
        existing = self.db.query(CVE).filter(
            CVE.cve_id == cve_data["cve_id"]
        ).first()

        if existing:
            logger.debug(f"CVE already exists: {cve_data['cve_id']}")
            return None

        # Handle CWE relationship
        cwe_obj = None
        cwe_ids = cve_data.get("cwe_ids", [])
        if cwe_ids:
            cwe_obj = self.get_or_create_cwe(cwe_ids[0])

        # Create CVE record
        cve = CVE(
            cve_id=cve_data["cve_id"],
            description=cve_data["description"],
            published_date=cve_data.get("published_date") or date.today(),
            cvss_score=cve_data.get("cvss_score"),
            severity=cve_data.get("severity"),
            exploit_type=cve_data.get("exploit_type"),
            cwe_id=cwe_obj.id if cwe_obj else None
        )

        self.db.add(cve)

        try:
            self.db.commit()
            self.db.refresh(cve)
            return cve
        except IntegrityError:
            self.db.rollback()
            logger.warning(f"Duplicate CVE skipped: {cve_data['cve_id']}")
            return None

    def save_many(self, cve_list: list[dict]) -> dict:
        """
        Save multiple CVEs with progress tracking.

        Args:
            cve_list: List of cleaned CVE dictionaries

        Returns:
            Summary dictionary with counts
        """
        saved = 0
        skipped = 0
        errors = 0

        for cve_data in cve_list:
            try:
                result = self.save_cve(cve_data)
                if result:
                    saved += 1
                else:
                    skipped += 1
            except Exception as e:
                logger.error(f"Error saving {cve_data.get('cve_id')}: {e}")
                errors += 1

        summary = {
            "saved": saved,
            "skipped": skipped,
            "errors": errors,
            "total": len(cve_list)
        }

        logger.success(f"Storage complete: {summary}")
        return summary

    def get_total_count(self) -> int:
        """Get total number of CVEs in database."""
        return self.db.query(CVE).count()