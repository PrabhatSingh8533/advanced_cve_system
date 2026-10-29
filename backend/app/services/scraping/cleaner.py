"""
Data Cleaning Pipeline for CVE descriptions and metadata.
Normalizes text, removes noise, standardizes formats.
"""

import re
import html
from typing import Optional
from loguru import logger


class CVECleaner:
    """
    Cleans and normalizes raw CVE data before NLP processing.
    """

    # Patterns to remove from descriptions
    NOISE_PATTERNS = [
        r"NOTE:.*?$",               # Remove NOTE: disclaimers
        r"\([\d\.]+\)",             # Remove version numbers in parens
        r"https?://\S+",            # Remove URLs
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # Remove IPs
        r"<[^>]+>",                 # Remove HTML tags
        r"\s+",                     # Normalize whitespace
    ]

    def clean_description(self, text: str) -> str:
        """
        Clean CVE description text.

        Args:
            text: Raw description string

        Returns:
            Cleaned and normalized description
        """
        if not text:
            return ""

        # Decode HTML entities (&amp; → &)
        text = html.unescape(text)

        # Remove HTML tags
        text = re.sub(r"<[^>]+>", " ", text)

        # Remove URLs
        text = re.sub(r"https?://\S+", "[URL]", text)

        # Remove IP addresses
        text = re.sub(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "[IP]",
            text
        )

        # Normalize whitespace
        text = re.sub(r"\s+", " ", text)

        # Strip leading/trailing whitespace
        text = text.strip()

        return text

    def normalize_cve_id(self, cve_id: str) -> str:
        """
        Normalize CVE ID format to 'CVE-YYYY-NNNNN'.

        Args:
            cve_id: Raw CVE ID string

        Returns:
            Normalized CVE ID
        """
        # Remove whitespace
        cve_id = cve_id.strip().upper()

        # Ensure proper format
        pattern = r"CVE-\d{4}-\d{4,7}"
        match = re.search(pattern, cve_id)
        if match:
            return match.group()

        logger.warning(f"Non-standard CVE ID format: {cve_id}")
        return cve_id

    def normalize_severity(self, severity: Optional[str]) -> Optional[str]:
        """
        Normalize severity to standard values.

        Returns:
            One of: CRITICAL, HIGH, MEDIUM, LOW, or None
        """
        if not severity:
            return None

        severity = severity.upper().strip()
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

        if severity in valid:
            return severity

        # Handle edge cases
        mapping = {
            "INFORMATIONAL": "LOW",
            "IMPORTANT": "HIGH",
            "MODERATE": "MEDIUM",
        }
        return mapping.get(severity, "UNKNOWN")

    def extract_exploit_type(self, description: str) -> str:
        """
        Extract exploit type from CVE description using keywords.

        Args:
            description: Cleaned CVE description

        Returns:
            Exploit type string
        """
        description_lower = description.lower()

        exploit_types = {
            "Remote Code Execution": [
                "remote code execution", "rce", "arbitrary code"
            ],
            "SQL Injection": [
                "sql injection", "sqli", "sql query"
            ],
            "Cross-Site Scripting": [
                "cross-site scripting", "xss", "script injection"
            ],
            "Buffer Overflow": [
                "buffer overflow", "stack overflow", "heap overflow"
            ],
            "Path Traversal": [
                "path traversal", "directory traversal", "../"
            ],
            "Denial of Service": [
                "denial of service", "dos", "crash", "deadlock"
            ],
            "Privilege Escalation": [
                "privilege escalation", "elevat", "root access"
            ],
            "Information Disclosure": [
                "information disclosure", "data leak", "sensitive data"
            ],
            "Authentication Bypass": [
                "authentication bypass", "bypass authentication",
                "unauthenticated"
            ],
            "CSRF": [
                "cross-site request forgery", "csrf"
            ],
        }

        for exploit_type, keywords in exploit_types.items():
            if any(kw in description_lower for kw in keywords):
                return exploit_type

        return "Other"

    def clean_cve_record(self, cve: dict) -> dict:
        """
        Apply full cleaning pipeline to a parsed CVE record.

        Args:
            cve: Parsed CVE dictionary from NVDParser

        Returns:
            Fully cleaned CVE dictionary
        """
        try:
            cleaned = cve.copy()

            # Clean fields
            cleaned["cve_id"] = self.normalize_cve_id(cve.get("cve_id", ""))
            cleaned["description"] = self.clean_description(
                cve.get("description", "")
            )
            cleaned["severity"] = self.normalize_severity(
                cve.get("severity")
            )
            cleaned["exploit_type"] = self.extract_exploit_type(
                cleaned["description"]
            )

            return cleaned

        except Exception as e:
            logger.error(f"Error cleaning CVE record: {e}")
            return cve

    def clean_many(self, cves: list[dict]) -> list[dict]:
        """Clean a list of CVE records."""
        cleaned = [self.clean_cve_record(cve) for cve in cves]
        logger.info(f"Cleaned {len(cleaned)} CVE records")
        return cleaned