"""CVE Text Cleaning and Normalization."""
import re
import html
import unicodedata
from loguru import logger


class CVETextCleaner:
    """Cleans and normalizes raw CVE description text."""

    def __init__(self):
        self.html_tags = re.compile(r"<[^>]+>")
        self.urls = re.compile(r"https?://\S+")
        self.ip_pattern = re.compile(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        )
        self.versions = re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")
        self.hashes = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
        self.whitespace = re.compile(r"\s+")
        self.cve_pattern = re.compile(
            r"CVE-\d{4}-\d{4,7}", re.IGNORECASE
        )
        logger.info("CVETextCleaner initialized")

    def full_clean(
        self,
        text: str,
        tokenize_versions: bool = True,
        tokenize_urls: bool = True,
        tokenize_ips: bool = True
    ) -> str:
        """Apply complete cleaning pipeline to CVE text."""
        if not text or not isinstance(text, str):
            return ""
        text = html.unescape(text)
        text = self.html_tags.sub(" ", text)
        text = unicodedata.normalize("NFC", text)
        text = self.cve_pattern.sub(
            lambda m: m.group().upper(), text
        )
        text = self.hashes.sub("[HASH]", text)
        if tokenize_urls:
            text = self.urls.sub("[URL]", text)
        if tokenize_ips:
            text = self.ip_pattern.sub("[IP]", text)
        if tokenize_versions:
            text = self.versions.sub("[VERSION]", text)
        text = self.whitespace.sub(" ", text).strip()
        return text

    def batch_clean(self, texts: list, **kwargs) -> list:
        """Clean a batch of texts."""
        return [self.full_clean(t, **kwargs) for t in texts]
