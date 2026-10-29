"""
CVE Data Collection Orchestrator.
Coordinates NVD fetching, parsing, cleaning, and storage.
"""

from datetime import datetime, timedelta
from loguru import logger
from sqlalchemy.orm import Session

from app.services.scraping.nvd_client import NVDClient
from app.services.scraping.nvd_parser import NVDParser
from app.services.scraping.cleaner import CVECleaner
from app.services.scraping.storage import CVEStorageService


class CVECollector:
    """
    Main orchestrator that ties together:
    NVD API → Parser → Cleaner → Database
    """

    def __init__(self, db: Session):
        self.db = db
        self.client = NVDClient()
        self.parser = NVDParser()
        self.cleaner = CVECleaner()
        self.storage = CVEStorageService(db)

    def collect_recent(self, days: int = 7) -> dict:
        """
        Collect CVEs from the last N days.

        Args:
            days: Number of days to look back

        Returns:
            Collection summary
        """
        logger.info(f"Starting collection for last {days} days")

        # Step 1: Fetch from NVD API
        raw_cves = self.client.fetch_recent_cves(days=days)

        # Step 2: Parse raw data
        parsed_cves = self.parser.parse_many(raw_cves)

        # Step 3: Clean data
        cleaned_cves = self.cleaner.clean_many(parsed_cves)

        # Step 4: Save to database
        summary = self.storage.save_many(cleaned_cves)

        total_in_db = self.storage.get_total_count()
        summary["total_in_database"] = total_in_db

        logger.success(f"Collection done! DB now has {total_in_db} CVEs")
        return summary

    def collect_by_year(self, year: int) -> dict:
        """
        Collect all CVEs for a specific year.

        Args:
            year: Year to collect (e.g., 2023)

        Returns:
            Collection summary
        """
        start = datetime(year, 1, 1)
        end = datetime(year, 12, 31, 23, 59, 59)

        logger.info(f"Collecting all CVEs for year {year}")

        # Fetch in 90-day chunks to avoid API limits
        all_raw = []
        chunk_start = start

        while chunk_start < end:
            chunk_end = min(chunk_start + timedelta(days=90), end)

            raw = self.client.fetch_cves_by_date_range(chunk_start, chunk_end)
            all_raw.extend(raw)

            chunk_start = chunk_end + timedelta(seconds=1)

        parsed = self.parser.parse_many(all_raw)
        cleaned = self.cleaner.clean_many(parsed)
        summary = self.storage.save_many(cleaned)

        return summary