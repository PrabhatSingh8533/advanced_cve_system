"""Named Entity Recognition for CVE text."""
import re
import subprocess
from loguru import logger


class CVEEntityExtractor:
    """Extracts security entities from CVE descriptions."""

    ATTACK_PATTERNS = {
        "RCE": ["remote code execution", "arbitrary code", "rce"],
        "SQLi": ["sql injection", "sqli"],
        "XSS": ["cross-site scripting", "xss"],
        "Buffer_Overflow": [
            "buffer overflow", "heap overflow", "stack overflow"
        ],
        "Path_Traversal": ["path traversal", "directory traversal"],
        "DoS": ["denial of service", "dos", "crash"],
        "Privilege_Escalation": [
            "privilege escalation", "gain privileges"
        ],
        "Auth_Bypass": [
            "authentication bypass", "unauthenticated"
        ],
        "Info_Disclosure": ["information disclosure", "data leak"],
        "SSRF": ["server-side request forgery", "ssrf"],
        "XXE": ["xml external entity", "xxe"],
        "Deserialization": [
            "deserialization", "unsafe deserialization"
        ],
    }

    SEVERITY_WORDS = {
        "CRITICAL": ["critical", "severe", "wormable"],
        "HIGH": ["high", "significant", "important"],
        "MEDIUM": ["medium", "moderate"],
        "LOW": ["low", "minor", "minimal"]
    }

    def __init__(self, model: str = "en_core_web_sm"):
        try:
            import spacy
            self.nlp = spacy.load(model)
        except OSError:
            subprocess.run(
                ["python", "-m", "spacy", "download", model],
                check=True
            )
            import spacy
            self.nlp = spacy.load(model)

        self.cve_re = re.compile(
            r"CVE-\d{4}-\d{4,7}", re.IGNORECASE
        )
        self.cwe_re = re.compile(r"CWE-\d+", re.IGNORECASE)
        self.cvss_re = re.compile(
            r"(?:CVSS|score)[:\s]+(\d+(?:\.\d+)?)",
            re.IGNORECASE
        )
        logger.info("CVEEntityExtractor initialized")

    def extract_cve_ids(self, text: str) -> list:
        return [m.upper() for m in self.cve_re.findall(text)]

    def extract_cwe_ids(self, text: str) -> list:
        return [m.upper() for m in self.cwe_re.findall(text)]

    def extract_cvss_scores(self, text: str) -> list:
        scores = []
        for m in self.cvss_re.findall(text):
            try:
                s = float(m)
                if 0.0 <= s <= 10.0:
                    scores.append(s)
            except ValueError:
                pass
        return scores

    def extract_attack_types(self, text: str) -> list:
        tl = text.lower()
        return [
            at for at, kws in self.ATTACK_PATTERNS.items()
            if any(kw in tl for kw in kws)
        ]

    def extract_severity_indicator(self, text: str):
        tl = text.lower()
        for sev, words in self.SEVERITY_WORDS.items():
            if any(w in tl for w in words):
                return sev
        return None

    def extract_software_entities(self, text: str) -> list:
        doc = self.nlp(text)
        return [
            {"text": e.text, "label": e.label_}
            for e in doc.ents
            if e.label_ in ["ORG", "PRODUCT", "GPE"]
        ]

    def extract_all(self, text: str) -> dict:
        return {
            "cve_ids": self.extract_cve_ids(text),
            "cwe_ids": self.extract_cwe_ids(text),
            "cvss_scores": self.extract_cvss_scores(text),
            "attack_types": self.extract_attack_types(text),
            "severity_indicator": self.extract_severity_indicator(text),
            "software_entities": self.extract_software_entities(text),
        }
