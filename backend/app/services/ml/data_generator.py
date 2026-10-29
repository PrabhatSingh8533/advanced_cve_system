"""
Training Data Generator - Rich CVE examples for better F1.
"""

import re
import json
import random
from pathlib import Path
from typing import Optional
from loguru import logger


class CVETrainingDataGenerator:
    """Generates rich training data for BERT fine-tuning."""

    EXPLOIT_EXAMPLES = {
        "Remote Code Execution": [
            "allows remote attackers to execute arbitrary code via crafted HTTP request",
            "enables remote code execution through deserialization of untrusted data",
            "permits unauthenticated remote code execution via command injection",
            "results in arbitrary command execution on the server",
            "allows execution of arbitrary code with root privileges",
            "enables attacker to run malicious code through JNDI injection",
            "remote code execution vulnerability in the parsing component",
            "arbitrary code execution possible via specially crafted payload",
            "unauthenticated RCE via template injection in web interface",
            "code execution vulnerability exploitable by remote unauthenticated attacker",
            "allows remote execution of operating system commands",
            "execute arbitrary commands on the underlying operating system",
            "remote attackers can execute code via buffer overflow exploitation",
            "enables shell command execution through improper input sanitization",
            "critical RCE flaw allows full system compromise remotely",
            "attacker controlled LDAP endpoint leads to code execution",
            "arbitrary code execution via malicious serialized Java object",
            "remote code execution through XML external entity injection",
            "allows executing arbitrary PHP code via file upload vulnerability",
            "server-side template injection leads to remote code execution",
        ],
        "SQL Injection": [
            "allows SQL injection via the id parameter in search function",
            "SQL injection vulnerability in login form via username field",
            "blind SQL injection possible through order parameter manipulation",
            "permits database enumeration via time-based SQL injection",
            "allows extraction of password hashes via UNION-based SQL injection",
            "SQL injection in admin panel allows complete database access",
            "unauthenticated SQL injection via REST API endpoint",
            "stored SQL injection allows persistent database manipulation",
            "error-based SQL injection reveals database structure",
            "SQL injection via HTTP header leads to data exfiltration",
            "allows attacker to bypass authentication using SQL injection",
            "database contents exposed via second-order SQL injection",
            "SQL injection in search parameter allows file read",
            "integer SQL injection via product ID parameter",
            "SQL injection vulnerability allows dropping database tables",
            "out-of-band SQL injection via DNS exfiltration",
            "SQL injection in cookie value allows session hijacking",
            "allows reading arbitrary files via SQL injection load_file",
            "SQL injection leads to unauthorized admin account creation",
            "NoSQL injection vulnerability allows authentication bypass",
        ],
        "Cross-Site Scripting": [
            "stored XSS vulnerability in comment field allows script injection",
            "reflected cross-site scripting via search parameter",
            "DOM-based XSS through URL fragment manipulation",
            "persistent XSS in user profile allows cookie theft",
            "cross-site scripting in error message reveals user data",
            "allows injection of arbitrary JavaScript via message parameter",
            "XSS vulnerability in admin panel affects all users",
            "self-XSS vulnerability via crafted SVG file upload",
            "cross-site scripting through HTTP response header injection",
            "blind XSS via contact form field",
            "XSS in markdown renderer allows script execution",
            "stored XSS via filename in file upload functionality",
            "reflected XSS in redirect URL parameter",
            "allows stealing session cookies via cross-site scripting",
            "XSS vulnerability in web application allows phishing attacks",
            "cross-site scripting via JSON response without content-type",
            "mXSS through HTML sanitizer bypass",
            "XSS via postMessage without origin verification",
            "allows executing JavaScript in victim browser context",
            "cross-site scripting in PDF export functionality",
        ],
        "Buffer Overflow": [
            "stack-based buffer overflow in image parsing library",
            "heap buffer overflow via malformed network packet",
            "buffer overflow in string handling function allows code execution",
            "stack overflow vulnerability triggered by long username field",
            "heap-based buffer overflow in media player codec",
            "out-of-bounds write via crafted font file",
            "buffer overflow in PDF parsing allows arbitrary code execution",
            "integer overflow leads to heap buffer overflow",
            "stack buffer overflow in VPN client certificate parsing",
            "memory corruption via oversized DHCP packet",
            "global buffer overflow in XML parser",
            "buffer overflow in network protocol implementation",
            "use-after-free vulnerability in browser rendering engine",
            "double-free vulnerability leads to memory corruption",
            "buffer overflow via specially crafted TIFF image file",
            "out-of-bounds read in audio file parser",
            "heap spray via malformed JavaScript leads to overflow",
            "buffer overflow in zip file extraction routine",
            "stack smashing detected in authentication module",
            "buffer overflow via excessively long HTTP header value",
        ],
        "Denial of Service": [
            "allows remote attackers to cause denial of service via malformed request",
            "null pointer dereference causes application crash",
            "infinite loop in XML parser leads to CPU exhaustion",
            "memory exhaustion via unrestricted file upload",
            "remote denial of service via crafted UDP packet",
            "resource exhaustion through excessive API requests",
            "application crash via division by zero error",
            "denial of service via deeply nested JSON structure",
            "uncontrolled recursion causes stack exhaustion crash",
            "memory leak in long-running process causes OOM crash",
            "denial of service via crafted TLS ClientHello message",
            "deadlock condition causes service hang indefinitely",
            "amplification attack possible via misconfigured DNS server",
            "crash via integer underflow in packet length calculation",
            "denial of service through thread pool exhaustion",
            "remote crash via specially crafted HTTP/2 frame",
            "assertion failure causes process termination",
            "denial of service via slow HTTP POST attack",
            "unhandled exception causes service unavailability",
            "denial of service via zip bomb decompression",
        ],
        "Privilege Escalation": [
            "local privilege escalation via SUID binary exploitation",
            "allows unprivileged user to gain root access",
            "privilege escalation through race condition in setuid program",
            "local user can escalate to administrator via weak permissions",
            "privilege escalation via insecure temporary file creation",
            "allows gaining elevated privileges through DLL injection",
            "local privilege escalation via kernel driver vulnerability",
            "elevation of privilege through COM object hijacking",
            "privilege escalation via symlink attack on sensitive file",
            "allows local user to read root-owned files",
            "privilege escalation via PATH environment variable manipulation",
            "gains SYSTEM privileges through service misconfiguration",
            "local privilege escalation via sudo configuration weakness",
            "elevation of privilege through token impersonation",
            "privilege escalation via insecure deserialization in local service",
            "allows container escape and host privilege escalation",
            "local privilege escalation via cron job manipulation",
            "gains elevated privileges through registry key weakness",
            "privilege escalation via weak file permission on config",
            "allows switching from guest to admin account locally",
        ],
        "Path Traversal": [
            "directory traversal via ../ sequences in filename parameter",
            "path traversal allows reading arbitrary files from server",
            "allows accessing files outside web root via path manipulation",
            "file inclusion vulnerability via path traversal in include parameter",
            "arbitrary file read via traversal in download endpoint",
            "path traversal in zip extraction allows overwriting system files",
            "allows reading /etc/passwd via path traversal vulnerability",
            "directory traversal in file manager component",
            "path traversal via URL-encoded dot-dot sequences",
            "allows reading sensitive configuration files via traversal",
            "path traversal in template engine allows file disclosure",
            "file traversal via null byte injection in filename",
            "allows overwriting arbitrary files via path traversal",
            "path traversal through symlink following in extraction",
            "reading private keys via path traversal in API endpoint",
        ],
        "Authentication Bypass": [
            "allows bypassing authentication via empty password string",
            "authentication bypass via SQL injection in login",
            "JWT algorithm confusion allows forging valid tokens",
            "authentication bypass through HTTP header manipulation",
            "allows accessing admin panel without valid credentials",
            "OAuth token validation bypass allows account takeover",
            "authentication bypass via race condition in login",
            "allows authentication bypass using crafted cookie value",
            "multi-factor authentication bypass via response manipulation",
            "authentication bypass through LDAP injection",
            "allows login with expired or revoked session token",
            "password reset bypass via predictable token generation",
            "authentication bypass via XML signature wrapping attack",
            "allows bypassing 2FA through SIM swapping vulnerability",
            "authentication bypass via HTTP request smuggling",
        ],
        "Information Disclosure": [
            "allows reading arbitrary files via path traversal",
            "sensitive information disclosure via verbose error messages",
            "memory disclosure via uninitialized buffer in response",
            "allows reading private API keys from configuration endpoint",
            "information disclosure through timing side-channel attack",
            "exposes internal IP addresses in HTTP response headers",
            "allows reading other users private messages",
            "source code disclosure via backup file exposure",
            "sensitive data exposure via insecure direct object reference",
            "allows extracting encryption keys via cache timing attack",
            "discloses database credentials via debug endpoint",
            "information leakage through HTTP response differences",
            "allows reading admin credentials from configuration file",
            "sensitive PII exposed via misconfigured S3 bucket",
            "discloses internal network topology via SSRF vulnerability",
        ],
    }

    def __init__(
        self, output_dir: str = "app/data/training"
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        random.seed(42)
        logger.info("CVETrainingDataGenerator initialized")

    def generate_classification_dataset(
        self, samples_per_class: int = 50
    ) -> list:
        """Generate classification dataset with augmentation."""
        dataset = []
        label_map = self.get_label_map()

        for exploit_type, examples in self.EXPLOIT_EXAMPLES.items():
            label_id = label_map[exploit_type]

            # Use all examples + augmentations
            all_texts = list(examples)

            # Add augmented versions
            for ex in examples:
                all_texts.extend(self._augment(ex))

            # Add CVE-format prefixes
            final_texts = []
            for text in all_texts:
                for prefix in self._get_prefixes():
                    final_texts.append(f"{prefix}{text}.")

            # Sample required amount
            random.shuffle(final_texts)
            selected = final_texts[:samples_per_class]

            for text in selected:
                dataset.append({
                    "text": text,
                    "label": exploit_type,
                    "label_id": label_id
                })

        random.shuffle(dataset)
        logger.info(
            f"Generated {len(dataset)} samples | "
            f"{len(self.EXPLOIT_EXAMPLES)} classes"
        )
        return dataset

    def _get_prefixes(self) -> list:
        """Generate CVE-like text prefixes."""
        years = list(range(2019, 2025))
        prefixes = []
        for _ in range(5):
            year = random.choice(years)
            num = random.randint(1000, 99999)
            prefixes.extend([
                f"CVE-{year}-{num}: ",
                f"A vulnerability was found that ",
                f"An issue was discovered which ",
                f"",
                f"Researchers discovered that ",
                f"The affected software ",
            ])
        return prefixes

    def _augment(self, text: str) -> list:
        """Augment text with synonym replacements."""
        augmented = []
        swaps = [
            ("allows", "permits"),
            ("allows", "enables"),
            ("attackers", "adversaries"),
            ("attackers", "threat actors"),
            ("arbitrary", "malicious"),
            ("arbitrary", "attacker-controlled"),
            ("remote", "network-adjacent"),
            ("via", "through"),
            ("via", "by means of"),
        ]
        for original, replacement in swaps:
            if original in text:
                augmented.append(
                    text.replace(original, replacement, 1)
                )
        return augmented[:3]

    def generate_from_db(self, db) -> list:
        """Generate training data from real CVEs in database."""
        from app.db.models.cve import CVE
        label_map = self.get_label_map()

        try:
            cves = db.query(CVE).filter(
                CVE.description.isnot(None),
                CVE.exploit_type.isnot(None)
            ).limit(2000).all()

            dataset = []
            for cve in cves:
                if cve.exploit_type in label_map:
                    dataset.append({
                        "text": cve.description[:512],
                        "label": cve.exploit_type,
                        "label_id": label_map[cve.exploit_type],
                        "cve_id": cve.cve_id
                    })

            logger.info(f"DB samples: {len(dataset)}")
            return dataset
        except Exception as e:
            logger.error(f"DB fetch error: {e}")
            return []

    def get_label_map(self) -> dict:
        return {
            label: idx
            for idx, label in enumerate(self.EXPLOIT_EXAMPLES.keys())
        }

    def get_id_label_map(self) -> dict:
        return {v: k for k, v in self.get_label_map().items()}

    def save_dataset(self, dataset: list, filename: str) -> str:
        path = self.output_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(dataset, f, indent=2)
        logger.info(f"Dataset saved: {path} ({len(dataset)} samples)")
        return str(path)

    def load_dataset(self, filename: str) -> list:
        path = self.output_dir / filename
        with open(path) as f:
            return json.load(f)
