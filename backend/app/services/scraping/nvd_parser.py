"""
NVD Response Parser.
Extracts and normalizes fields from raw NVD API responses.
"""

from datetime import datetime
from typing import Optional
from loguru import logger


class NVDParser:
    """
    Parses raw NVD API JSON into clean structured dictionaries
    ready for database insertion.
    """

    # CVSS score to severity mapping
    SEVERITY_MAP = {
        (0.0, 3.9): "LOW",
        (4.0, 6.9): "MEDIUM",
        (7.0, 8.9): "HIGH",
        (9.0, 10.0): "CRITICAL"
    }

    def parse_cve(self, raw_cve: dict) -> Optional[dict]:
        """
        Parse a single raw NVD CVE entry.

        Args:
            raw_cve: Raw dictionary from NVD API response

        Returns:
            Clean CVE dictionary ready for database, or None if invalid
        """
        try:
            cve_data = raw_cve.get("cve", {})

            # --- CVE ID ---
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # --- Description (English only) ---
            description = self._extract_description(cve_data)

            # --- Dates ---
            published_date = self._parse_date(
                cve_data.get("published", "")
            )
            modified_date = self._parse_date(
                cve_data.get("lastModified", "")
            )

            # --- CVSS Score & Severity ---
            cvss_score, severity = self._extract_cvss(cve_data)

            # --- CWE ---
            cwe_ids = self._extract_cwes(cve_data)

            # --- References ---
            references = self._extract_references(cve_data)

            # --- CPE (Affected Products) ---
            affected_products = self._extract_cpe(cve_data)

            return {
                "cve_id": cve_id,
                "description": description,
                "published_date": published_date,
                "modified_date": modified_date,
                "cvss_score": cvss_score,
                "severity": severity,
                "cwe_ids": cwe_ids,
                "references": references,
                "affected_products": affected_products,
                "raw_data": cve_data  # Keep original for reference
            }

        except Exception as e:
            logger.error(f"Error parsing CVE: {e}")
            return None

    def _extract_description(self, cve_data: dict) -> str:
        """Extract English description from CVE data."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "No description available")
        return "No description available"

    def _parse_date(self, date_str: str) -> Optional[datetime.date]:
        """Parse ISO 8601 date string to date object."""
        if not date_str:
            return None
        try:
            # NVD format: "2021-12-10T10:15:09.143"
            return datetime.fromisoformat(
                date_str.replace("Z", "")
            ).date()
        except ValueError:
            logger.warning(f"Could not parse date: {date_str}")
            return None

    def _extract_cvss(self, cve_data: dict) -> tuple[Optional[float], Optional[str]]:
        """
        Extract CVSS score and severity.
        Tries CVSS v3.1 first, then v3.0, then v2.0.
        """
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                metric = metric_list[0]  # Take primary score
                cvss_data = metric.get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or self._score_to_severity(score)
                return score, severity

        return None, None

    def _score_to_severity(self, score: Optional[float]) -> Optional[str]:
        """Convert numeric CVSS score to severity label."""
        if score is None:
            return None
        for (low, high), severity in self.SEVERITY_MAP.items():
            if low <= score <= high:
                return severity
        return "UNKNOWN"

    def _extract_cwes(self, cve_data: dict) -> list[str]:
        """Extract CWE IDs from CVE data."""
        cwes = []
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwes.append(value)
        return cwes

    def _extract_references(self, cve_data: dict) -> list[str]:
        """Extract reference URLs."""
        refs = cve_data.get("references", [])
        return [ref.get("url", "") for ref in refs if ref.get("url")]

    def _extract_cpe(self, cve_data: dict) -> list[str]:
        """Extract affected product CPE strings."""
        products = []
        configs = cve_data.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        products.append(cpe_match.get("criteria", ""))
        return products[:10]  # Limit to 10 products

    def parse_many(self, raw_cves: list[dict]) -> list[dict]:
        """
        Parse a list of raw CVEs.

        Args:
            raw_cves: List of raw NVD API entries

        Returns:
            List of parsed CVE dictionaries (None values filtered out)
        """
        parsed = []
        for raw in raw_cves:
            result = self.parse_cve(raw)
            if result:
                parsed.append(result)

        logger.info(f"Parsed {len(parsed)}/{len(raw_cves)} CVEs successfully")
        return parsed