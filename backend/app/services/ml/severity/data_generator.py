"""
CVE Severity Training Data Generator - Real DB Version.
Uses actual NVD CVSS scores as ground truth.
"""

import random
import numpy as np
from loguru import logger


class SeverityDataGenerator:
    """
    Generates CVSS score training data.
    Prioritizes real NVD data over synthetic.
    """

    # Synthetic templates (fallback only)
    SEVERITY_TEMPLATES = {
        "CRITICAL": {
            "score_range": (9.0, 10.0),
            "templates": [
                "allows unauthenticated remote code execution via {vector}",
                "enables complete system compromise through {vector}",
                "wormable vulnerability allows propagation via {vector}",
                "critical RCE flaw exploitable without authentication via {vector}",
                "allows remote attackers to execute arbitrary code via {vector}",
                "unauthenticated attacker can gain full system control via {vector}",
                "zero-click remote code execution vulnerability in {component}",
                "pre-authentication RCE with no user interaction via {vector}",
                "allows complete confidentiality integrity availability impact via {vector}",
                "network-exploitable critical vulnerability in {component}",
            ]
        },
        "HIGH": {
            "score_range": (7.0, 8.9),
            "templates": [
                "allows authenticated remote code execution via {vector}",
                "privilege escalation to root via {vector}",
                "allows SQL injection leading to data exfiltration via {vector}",
                "heap buffer overflow allows arbitrary code execution via {vector}",
                "authentication bypass allows admin access via {vector}",
                "remote code execution requires low privileges via {vector}",
                "allows significant data breach through {vector}",
                "arbitrary file read with authentication via {vector}",
                "high impact vulnerability requiring user interaction via {vector}",
                "allows reading sensitive files on server via {vector}",
            ]
        },
        "MEDIUM": {
            "score_range": (4.0, 6.9),
            "templates": [
                "stored cross-site scripting via {vector}",
                "allows SQL injection with limited impact via {vector}",
                "authenticated path traversal allows file read via {vector}",
                "cross-site request forgery in {component}",
                "reflected XSS via {vector} requires user interaction",
                "information disclosure of sensitive data via {vector}",
                "allows moderate data manipulation via {vector}",
                "authenticated user can access other users data via {vector}",
                "medium severity vulnerability requires authentication via {vector}",
                "partial information disclosure via {vector}",
            ]
        },
        "LOW": {
            "score_range": (0.1, 3.9),
            "templates": [
                "minor information disclosure via {vector}",
                "low impact denial of service via {vector}",
                "allows reading non-sensitive configuration via {vector}",
                "minor security bypass with limited scope via {vector}",
                "low severity vulnerability requires local access via {vector}",
                "minimal impact vulnerability in {component}",
                "allows reading public information via {vector}",
                "low risk vulnerability requiring physical access via {vector}",
                "minor data exposure with no authentication impact via {vector}",
                "informational severity finding in {component}",
            ]
        }
    }

    VECTORS = [
        "crafted HTTP request", "malformed packet",
        "specially crafted URL", "user-supplied input",
        "crafted JSON payload", "malformed XML",
        "specially crafted file", "manipulated cookie",
        "crafted header", "user-controlled parameter",
    ]

    COMPONENTS = [
        "web application", "REST API", "authentication module",
        "file parser", "network daemon", "admin interface",
        "login form", "search function", "upload handler",
    ]

    PRODUCTS = [
        "Apache HTTP Server", "nginx", "OpenSSL", "WordPress",
        "Drupal", "Microsoft Exchange", "Oracle WebLogic",
        "Jenkins", "GitLab", "Kubernetes", "Docker",
        "Apache Tomcat", "Spring Framework", "Django",
    ]

    def __init__(self):
        random.seed(42)
        np.random.seed(42)
        logger.info("SeverityDataGenerator initialized")

    def generate_from_db(self, db) -> list:
        """
        Load REAL CVE data with CVSS scores from database.
        This is the PRIMARY data source - official NVD scores.
        """
        from app.db.models.cve import CVE

        logger.info("Loading real CVE data with CVSS scores from NVD...")

        cves = db.query(CVE).filter(
            CVE.description.isnot(None),
            CVE.description != "",
            CVE.cvss_score.isnot(None),
            CVE.cvss_score > 0.0,
            CVE.cvss_score <= 10.0
        ).all()

        dataset = []
        score_dist = {
            "CRITICAL": 0, "HIGH": 0,
            "MEDIUM": 0, "LOW": 0
        }
        skipped = 0

        for cve in cves:
            # Skip very short descriptions
            if len(cve.description) < 30:
                skipped += 1
                continue

            # Skip reserved/disputed
            desc_lower = cve.description.lower()
            if any(p in desc_lower for p in [
                "** reserved **", "** disputed **",
                "do not use this candidate"
            ]):
                skipped += 1
                continue

            score = float(cve.cvss_score)

            # Determine severity from score
            if score >= 9.0:
                sev = "CRITICAL"
            elif score >= 7.0:
                sev = "HIGH"
            elif score >= 4.0:
                sev = "MEDIUM"
            else:
                sev = "LOW"

            score_dist[sev] += 1

            dataset.append({
                "cve_id": cve.cve_id,
                "text": cve.description[:512],
                "cvss_score": score,
                "severity": sev,
                "source": "nvd_official"
            })

        logger.info(
            f"Real severity dataset: {len(dataset)} samples | "
            f"Skipped: {skipped} | "
            f"Distribution: {score_dist}"
        )

        return dataset

    def generate_synthetic_sample(self, severity: str) -> dict:
        """Generate one synthetic CVE sample."""
        import random
        config = self.SEVERITY_TEMPLATES[severity]
        low, high = config["score_range"]
        score = round(random.uniform(low, high), 1)

        template = random.choice(config["templates"])
        vector = random.choice(self.VECTORS)
        component = random.choice(self.COMPONENTS)
        product = random.choice(self.PRODUCTS)
        year = random.randint(2018, 2024)
        num = random.randint(1000, 99999)

        description = template.format(
            vector=vector, component=component
        )
        prefix = random.choice([
            f"CVE-{year}-{num}: ",
            f"A vulnerability in {product} ",
            f"",
        ])

        return {
            "text": f"{prefix}{description}.",
            "cvss_score": score,
            "severity": severity,
            "source": "synthetic"
        }

    def generate_dataset(
        self,
        samples_per_severity: int = 100
    ) -> list:
        """
        Generate SYNTHETIC dataset (fallback only).
        Used when DB has insufficient data.
        """
        dataset = []
        for severity in self.SEVERITY_TEMPLATES:
            for _ in range(samples_per_severity):
                dataset.append(
                    self.generate_synthetic_sample(severity)
                )

        import random
        random.shuffle(dataset)
        logger.info(
            f"Generated {len(dataset)} synthetic samples"
        )
        return dataset
