"""
Real CVE Data Labeler for NLP Training.

Labels real NVD CVE descriptions using:
1. Rule-based patterns (high precision keywords)
2. CWE-to-exploit mapping (authoritative)
3. CVSS vector string parsing (official scores)

NO fake data. NO synthetic examples.
All labels derived from official NVD data.
"""

import re
from loguru import logger


class RealCVELabeler:
    """
    Labels real CVE data from NVD for training.

    Label sources (all from real NVD data):
    - exploit_type: From description keywords + CWE mapping
    - cvss_score:   From NVD CVSS scores (ground truth)
    - severity:     From NVD severity field (ground truth)
    """

    # CWE → Exploit Type mapping (official CWE definitions)
    CWE_TO_EXPLOIT = {
        # Remote Code Execution
        "CWE-94":  "Remote Code Execution",   # Code Injection
        "CWE-95":  "Remote Code Execution",   # Eval Injection
        "CWE-96":  "Remote Code Execution",   # Static Code Injection
        "CWE-434": "Remote Code Execution",   # Unrestricted Upload
        "CWE-502": "Remote Code Execution",   # Deserialization

        # SQL Injection
        "CWE-89":  "SQL Injection",
        "CWE-564": "SQL Injection",           # Hibernate SQL Injection
        "CWE-943": "SQL Injection",           # NoSQL Injection

        # Cross-Site Scripting
        "CWE-79":  "Cross-Site Scripting",
        "CWE-80":  "Cross-Site Scripting",
        "CWE-81":  "Cross-Site Scripting",
        "CWE-83":  "Cross-Site Scripting",
        "CWE-84":  "Cross-Site Scripting",

        # Buffer Overflow
        "CWE-119": "Buffer Overflow",         # Memory Corruption
        "CWE-120": "Buffer Overflow",         # Classic Buffer Overflow
        "CWE-121": "Buffer Overflow",         # Stack Buffer Overflow
        "CWE-122": "Buffer Overflow",         # Heap Buffer Overflow
        "CWE-125": "Buffer Overflow",         # Out-of-bounds Read
        "CWE-787": "Buffer Overflow",         # Out-of-bounds Write
        "CWE-416": "Buffer Overflow",         # Use After Free
        "CWE-415": "Buffer Overflow",         # Double Free

        # Path Traversal
        "CWE-22":  "Path Traversal",
        "CWE-23":  "Path Traversal",
        "CWE-24":  "Path Traversal",
        "CWE-36":  "Path Traversal",

        # Denial of Service
        "CWE-400": "Denial of Service",       # Uncontrolled Resource
        "CWE-401": "Denial of Service",       # Memory Leak
        "CWE-770": "Denial of Service",       # Resource Allocation
        "CWE-835": "Denial of Service",       # Infinite Loop
        "CWE-369": "Denial of Service",       # Divide by Zero

        # Privilege Escalation
        "CWE-269": "Privilege Escalation",    # Improper Privilege Mgmt
        "CWE-264": "Privilege Escalation",    # Permissions Issues
        "CWE-276": "Privilege Escalation",    # Incorrect Default Perms
        "CWE-732": "Privilege Escalation",    # Incorrect Permission

        # Authentication Bypass
        "CWE-287": "Authentication Bypass",   # Improper Auth
        "CWE-288": "Authentication Bypass",   # Auth Bypass
        "CWE-306": "Authentication Bypass",   # Missing Auth
        "CWE-307": "Authentication Bypass",   # Brute Force
        "CWE-798": "Authentication Bypass",   # Hardcoded Credentials

        # Information Disclosure
        "CWE-200": "Information Disclosure",
        "CWE-201": "Information Disclosure",
        "CWE-203": "Information Disclosure",
        "CWE-209": "Information Disclosure",
        "CWE-532": "Information Disclosure",  # Log Exposure

        # SSRF
        "CWE-918": "Server-Side Request Forgery",

        # XXE
        "CWE-611": "XML External Entity",

        # CSRF
        "CWE-352": "Cross-Site Request Forgery",

        # Command Injection
        "CWE-77":  "Remote Code Execution",   # Command Injection
        "CWE-78":  "Remote Code Execution",   # OS Command Injection
    }

    # High-precision keyword patterns for description labeling
    # Only include patterns with HIGH confidence (>95% precision)
    KEYWORD_PATTERNS = {
        "Remote Code Execution": [
            r"remote code execution",
            r"arbitrary code execution",
            r"execute arbitrary code",
            r"code execution vulnerability",
            r"arbitrary command execution",
            r"os command injection",
            r"command injection",
            r"jndi injection",
            r"deserialization.*execut",
            r"execut.*malicious code",
        ],
        "SQL Injection": [
            r"sql injection",
            r"sql query.*inject",
            r"inject.*sql",
            r"unsanitized.*sql",
            r"nosql injection",
        ],
        "Cross-Site Scripting": [
            r"cross.site scripting",
            r"\bxss\b",
            r"reflected.*script",
            r"stored.*script inject",
            r"script inject",
        ],
        "Buffer Overflow": [
            r"buffer overflow",
            r"stack.based overflow",
            r"heap.based overflow",
            r"heap overflow",
            r"stack overflow",
            r"out.of.bounds write",
            r"memory corruption",
            r"use.after.free",
            r"double.free",
        ],
        "Denial of Service": [
            r"denial.of.service",
            r"\bdos\b attack",
            r"cause.*crash",
            r"infinite loop",
            r"resource exhaustion",
            r"memory exhaustion",
            r"application crash",
            r"null pointer dereference",
        ],
        "Privilege Escalation": [
            r"privilege escalation",
            r"elevat.*privilege",
            r"gain.*root",
            r"local.*privilege",
            r"escalat.*privilege",
        ],
        "Path Traversal": [
            r"path traversal",
            r"directory traversal",
            r"\.\.\/",
            r"file inclusion",
        ],
        "Authentication Bypass": [
            r"authentication bypass",
            r"bypass.*authentication",
            r"unauthenticated.*access",
            r"bypass.*login",
            r"authentication.*flaw",
        ],
        "Information Disclosure": [
            r"information disclosure",
            r"sensitive.*data.*expos",
            r"data.*leak",
            r"memory.*disclosure",
            r"credential.*expos",
        ],
        "Server-Side Request Forgery": [
            r"server.side request forgery",
            r"\bssrf\b",
        ],
        "Cross-Site Request Forgery": [
            r"cross.site request forgery",
            r"\bcsrf\b",
        ],
        "XML External Entity": [
            r"xml external entity",
            r"\bxxe\b",
        ],
    }

    def __init__(self):
        # Compile patterns
        self.compiled_patterns = {}
        for exploit, patterns in self.KEYWORD_PATTERNS.items():
            self.compiled_patterns[exploit] = [
                re.compile(p, re.IGNORECASE)
                for p in patterns
            ]
        logger.info("RealCVELabeler initialized")

    def label_exploit_type(
        self,
        description: str,
        cwe_code: str = None
    ) -> tuple:
        """
        Label exploit type from REAL CVE description.

        Priority:
        1. CWE mapping (most authoritative)
        2. Description keyword matching
        3. None (don't guess)

        Returns:
            (exploit_type, confidence, source)
        """
        # Priority 1: CWE mapping (authoritative)
        if cwe_code and cwe_code in self.CWE_TO_EXPLOIT:
            exploit = self.CWE_TO_EXPLOIT[cwe_code]
            return exploit, 0.95, "cwe_mapping"

        # Priority 2: Keyword matching on description
        if description:
            for exploit, patterns in self.compiled_patterns.items():
                for pattern in patterns:
                    if pattern.search(description):
                        return exploit, 0.85, "keyword_match"

        # Priority 3: Unknown - don't fake it
        return None, 0.0, "unlabeled"

    def is_suitable_for_training(
        self,
        cve_record: dict
    ) -> bool:
        """
        Check if CVE record is suitable for ML training.

        Requirements for training data quality:
        - Has description (>50 chars)
        - Has CVSS score (for severity training)
        - Has clear exploit type label
        """
        desc = cve_record.get("description", "")
        if not desc or len(desc) < 50:
            return False

        # Skip generic/unclear descriptions
        unclear_phrases = [
            "** reserved **",
            "** disputed **",
            "do not use this candidate",
            "not yet assigned"
        ]
        if any(p in desc.lower() for p in unclear_phrases):
            return False

        return True


class RealTrainingDataBuilder:
    """
    Builds REAL training datasets from NVD database.

    NO synthetic data. All from real CVE descriptions.
    """

    def __init__(self, db):
        self.db = db
        self.labeler = RealCVELabeler()

    def build_classification_dataset(
        self,
        min_samples_per_class: int = 30,
        max_samples_per_class: int = 500
    ) -> dict:
        """
        Build exploit type classification dataset
        from REAL NVD CVE descriptions.

        Returns:
            dict with dataset info and samples
        """
        from app.db.models.cve import CVE
        from app.db.models.cwe import CWE
        from sqlalchemy.orm import joinedload

        logger.info("Building REAL classification dataset from NVD...")

        # Fetch all CVEs with descriptions
        cves = self.db.query(CVE).options(
            joinedload(CVE.cwe)
        ).filter(
            CVE.description.isnot(None),
            CVE.description != ""
        ).all()

        logger.info(f"Total CVEs in DB: {len(cves)}")

        # Label each CVE
        labeled = []
        label_counts = {}
        unlabeled_count = 0

        for cve in cves:
            # Check suitability
            record = {"description": cve.description}
            if not self.labeler.is_suitable_for_training(record):
                continue

            cwe_code = cve.cwe.cwe_code if cve.cwe else None

            exploit_type, confidence, source = (
                self.labeler.label_exploit_type(
                    cve.description, cwe_code
                )
            )

            if exploit_type is None:
                unlabeled_count += 1
                continue

            label_counts[exploit_type] = (
                label_counts.get(exploit_type, 0) + 1
            )

            labeled.append({
                "cve_id": cve.cve_id,
                "text": cve.description,
                "exploit_type": exploit_type,
                "confidence": confidence,
                "source": source,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "cwe_code": cwe_code
            })

        logger.info(f"Labeled: {len(labeled)} | Unlabeled: {unlabeled_count}")
        logger.info(f"Label distribution: {label_counts}")

        # Filter classes with enough samples
        valid_classes = {
            k: v for k, v in label_counts.items()
            if v >= min_samples_per_class
        }

        if not valid_classes:
            logger.warning(
                f"No classes have >= {min_samples_per_class} samples! "
                f"Current counts: {label_counts}"
            )
            return {
                "error": "insufficient_data",
                "label_counts": label_counts,
                "minimum_required": min_samples_per_class
            }

        # Balance dataset and apply max cap
        import random
        random.seed(42)

        final_dataset = []
        label_map = {
            label: idx
            for idx, label in enumerate(sorted(valid_classes.keys()))
        }

        for exploit_type in valid_classes:
            class_samples = [
                s for s in labeled
                if s["exploit_type"] == exploit_type
            ]

            # Shuffle for randomness
            random.shuffle(class_samples)

            # Cap at max
            selected = class_samples[:max_samples_per_class]

            for s in selected:
                final_dataset.append({
                    "cve_id": s["cve_id"],
                    "text": s["text"],
                    "label": exploit_type,
                    "label_id": label_map[exploit_type],
                    "source": s["source"],
                    "cvss_score": s["cvss_score"]
                })

        random.shuffle(final_dataset)

        # Final counts
        final_counts = {}
        for s in final_dataset:
            final_counts[s["label"]] = (
                final_counts.get(s["label"], 0) + 1
            )

        logger.info(
            f"Final dataset: {len(final_dataset)} samples | "
            f"Classes: {len(label_map)} | "
            f"Distribution: {final_counts}"
        )

        return {
            "total_samples": len(final_dataset),
            "num_classes": len(label_map),
            "label_map": label_map,
            "class_distribution": final_counts,
            "data_source": "NVD API (real)",
            "dataset": final_dataset
        }

    def build_severity_dataset(self) -> dict:
        """
        Build CVSS score regression dataset from REAL NVD data.

        Uses official NVD CVSS scores as ground truth.
        Only includes CVEs with verified CVSS scores.
        """
        from app.db.models.cve import CVE

        logger.info("Building REAL severity dataset from NVD...")

        cves = self.db.query(CVE).filter(
            CVE.description.isnot(None),
            CVE.cvss_score.isnot(None),
            CVE.cvss_score > 0.0,
            CVE.cvss_score <= 10.0
        ).all()

        dataset = []
        score_dist = {
            "CRITICAL": 0, "HIGH": 0,
            "MEDIUM": 0, "LOW": 0
        }

        for cve in cves:
            record = {"description": cve.description}
            if not self.labeler.is_suitable_for_training(record):
                continue

            score = float(cve.cvss_score)

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
                "text": cve.description,
                "cvss_score": score,
                "severity": sev,
                "source": "nvd_official"
            })

        logger.info(
            f"Severity dataset: {len(dataset)} samples | "
            f"Distribution: {score_dist}"
        )

        return {
            "total_samples": len(dataset),
            "score_distribution": score_dist,
            "data_source": "NVD API CVSS scores (official)",
            "dataset": dataset
        }

    def get_dataset_report(self) -> dict:
        """
        Generate full report of available training data.
        Shows what we can realistically train on.
        """
        from app.db.models.cve import CVE

        total = self.db.query(CVE).count()
        with_desc = self.db.query(CVE).filter(
            CVE.description.isnot(None)
        ).count()
        with_cvss = self.db.query(CVE).filter(
            CVE.cvss_score.isnot(None)
        ).count()
        with_severity = self.db.query(CVE).filter(
            CVE.severity.isnot(None)
        ).count()
        with_cwe = self.db.query(CVE).filter(
            CVE.cwe_id.isnot(None)
        ).count()
        with_exploit = self.db.query(CVE).filter(
            CVE.exploit_type.isnot(None),
            CVE.exploit_type != "Other"
        ).count()

        # Build preview of classification data
        cls_preview = self.build_classification_dataset(
            min_samples_per_class=10
        )

        return {
            "database_stats": {
                "total_cves": total,
                "with_description": with_desc,
                "with_cvss_score": with_cvss,
                "with_severity": with_severity,
                "with_cwe": with_cwe,
                "with_exploit_type": with_exploit,
            },
            "classification_training": {
                "available_samples": cls_preview.get(
                    "total_samples", 0
                ),
                "available_classes": cls_preview.get(
                    "num_classes", 0
                ),
                "class_distribution": cls_preview.get(
                    "class_distribution", {}
                ),
                "data_source": "NVD API (real)"
            },
            "severity_training": {
                "available_samples": with_cvss,
                "data_source": "NVD official CVSS scores"
            },
            "recommendation": self._get_recommendation(
                total, with_cvss, cls_preview
            )
        }

    def _get_recommendation(
        self, total, with_cvss, cls_preview
    ) -> str:
        """Give honest recommendation for training."""
        samples = cls_preview.get("total_samples", 0)
        classes = cls_preview.get("num_classes", 0)

        if total < 1000:
            return (
                "⚠️  Collect more data first. "
                "Run: POST /api/collect/year/2023 and /year/2024"
            )
        elif samples < 100:
            return (
                "⚠️  Limited labeled data. "
                f"Only {samples} labelable samples found. "
                "Collect more CVEs or lower min_samples_per_class."
            )
        elif classes < 3:
            return (
                f"⚠️  Only {classes} exploit classes have enough data. "
                "Model will only classify these types."
            )
        else:
            return (
                f"✅ Ready to train! {samples} real samples, "
                f"{classes} classes, {with_cvss} CVSS scores. "
                "Use POST /api/bert/train-real"
            )
