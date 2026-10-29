"""
NVD API Client - Fixed date format for 2025/2026.

NVD API v2.0 date format requirements:
- Format: YYYY-MM-DDTHH:MM:SS.000
- pubEndDate cannot be in the future
- Max range: 120 days per request
"""

import os
import time
import requests
from datetime import datetime, timedelta
from typing import Optional
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential
from dotenv import load_dotenv

load_dotenv()


class NVDClient:
    """
    NVD REST API v2.0 Client.
    Fixed for 2025/2026 date ranges.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.api_key = os.getenv("NVD_API_KEY", "")
        # Rate limits: with key=50/30s, without=5/30s
        self.delay = 0.6 if self.api_key else 6.5
        self.session = requests.Session()

        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

        logger.info(
            f"NVD Client initialized | "
            f"API Key: {'Yes' if self.api_key else 'No'} | "
            f"Rate delay: {self.delay}s"
        )

    def _format_date(self, dt: datetime) -> str:
        """
        Format datetime for NVD API.
        NVD requires: YYYY-MM-DDTHH:MM:SS.000
        Must NOT exceed current UTC time.
        """
        # Never exceed current time (NVD rejects future dates)
        now = datetime.utcnow()
        if dt > now:
            dt = now - timedelta(minutes=5)  # 5 min buffer

        return dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=4, max=30)
    )
    def _make_request(self, params: dict) -> dict:
        """Make API request with retry logic."""
        try:
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=30
            )

            # Log full URL for debugging
            logger.debug(f"NVD Request: {response.url}")

            if response.status_code == 404:
                logger.error(
                    f"NVD 404 - Check date range. "
                    f"Params: {params}"
                )
                raise requests.exceptions.HTTPError(
                    f"404 Not Found: {response.url}",
                    response=response
                )

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP Error: {e}")
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection Error: {e}")
            raise
        except requests.exceptions.Timeout:
            logger.error("Request timed out after 30s")
            raise

    def fetch_cves_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        results_per_page: int = 100
    ) -> list:
        """
        Fetch CVEs between start and end dates.

        Key fixes:
        - Caps end_date at current UTC time
        - Uses correct date format
        - Splits ranges > 120 days automatically
        """
        all_cves = []
        now = datetime.utcnow()

        # Cap end date at NOW (NVD rejects future dates)
        if end_date > now:
            end_date = now - timedelta(minutes=2)
            logger.info(
                f"End date capped at current UTC: "
                f"{end_date.strftime('%Y-%m-%d %H:%M')}"
            )

        # Skip if start is after end
        if start_date >= end_date:
            logger.warning(
                f"Start date {start_date} >= end date {end_date}, skipping"
            )
            return []

        # NVD recommends max 120 days per request
        max_chunk_days = 100

        # Split into chunks if range is large
        chunks = []
        chunk_start = start_date
        while chunk_start < end_date:
            chunk_end = min(
                chunk_start + timedelta(days=max_chunk_days),
                end_date
            )
            chunks.append((chunk_start, chunk_end))
            chunk_start = chunk_end + timedelta(seconds=1)

        logger.info(
            f"Fetching CVEs: {start_date.strftime('%Y-%m-%d')} → "
            f"{end_date.strftime('%Y-%m-%d')} | "
            f"{len(chunks)} chunk(s)"
        )

        for chunk_idx, (cs, ce) in enumerate(chunks):
            logger.info(
                f"Chunk {chunk_idx+1}/{len(chunks)}: "
                f"{cs.strftime('%Y-%m-%d')} → {ce.strftime('%Y-%m-%d')}"
            )

            start_index = 0
            while True:
                params = {
                    "pubStartDate": self._format_date(cs),
                    "pubEndDate": self._format_date(ce),
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index
                }

                try:
                    data = self._make_request(params)
                except Exception as e:
                    logger.error(
                        f"Chunk {chunk_idx+1} failed: {e}"
                    )
                    break

                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                all_cves.extend(vulnerabilities)

                logger.info(
                    f"  Fetched {len(all_cves)} total | "
                    f"Chunk progress: {start_index + len(vulnerabilities)}"
                    f"/{total_results}"
                )

                if start_index + results_per_page >= total_results:
                    break

                start_index += results_per_page
                time.sleep(self.delay)

            # Pause between chunks
            if chunk_idx < len(chunks) - 1:
                time.sleep(self.delay * 2)

        logger.success(f"Fetch complete: {len(all_cves)} CVEs")
        return all_cves

    def fetch_cve_by_id(self, cve_id: str) -> Optional[dict]:
        """Fetch single CVE by ID."""
        params = {"cveId": cve_id}
        try:
            data = self._make_request(params)
            vulns = data.get("vulnerabilities", [])
            if vulns:
                logger.info(f"Fetched: {cve_id}")
                return vulns[0]
            logger.warning(f"Not found: {cve_id}")
            return None
        except Exception as e:
            logger.error(f"Error fetching {cve_id}: {e}")
            return None

    def fetch_recent_cves(self, days: int = 7) -> list:
        """
        Fetch CVEs from last N days.
        Always uses current UTC time as end date.
        """
        end_date = datetime.utcnow() - timedelta(minutes=2)
        start_date = end_date - timedelta(days=days)

        logger.info(
            f"Fetching recent CVEs: last {days} days | "
            f"{start_date.strftime('%Y-%m-%d')} → "
            f"{end_date.strftime('%Y-%m-%d')}"
        )

        return self.fetch_cves_by_date_range(start_date, end_date)

    def fetch_by_year(self, year: int) -> list:
        """
        Fetch all CVEs for a specific year.
        Handles current year correctly.
        """
        now = datetime.utcnow()
        current_year = now.year

        start = datetime(year, 1, 1, 0, 0, 0)

        if year == current_year:
            # Current year: collect up to now
            end = now - timedelta(minutes=2)
            logger.info(
                f"Current year {year}: collecting "
                f"Jan {year} → {end.strftime('%b %d, %Y')}"
            )
        elif year > current_year:
            logger.warning(
                f"Year {year} is in the future! "
                f"Collecting up to today instead."
            )
            end = now - timedelta(minutes=2)
        else:
            # Past year: full year
            end = datetime(year, 12, 31, 23, 59, 59)

        return self.fetch_cves_by_date_range(start, end)
