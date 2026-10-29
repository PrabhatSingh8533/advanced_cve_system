"""Unit Tests for NLP Text Cleaner."""

import pytest
from app.services.nlp.text_cleaner import CVETextCleaner


@pytest.fixture(scope="module")
def cleaner():
    return CVETextCleaner()


class TestCVETextCleaner:

    def test_removes_html_tags(self, cleaner):
        result = cleaner.full_clean("<b>CVE-2021-44228</b> vulnerability")
        assert "<b>" not in result
        assert "CVE-2021-44228" in result

    def test_replaces_urls(self, cleaner):
        result = cleaner.full_clean(
            "See https://nvd.nist.gov for details",
            tokenize_urls=True
        )
        assert "https://" not in result
        assert "[URL]" in result

    def test_replaces_ip_addresses(self, cleaner):
        result = cleaner.full_clean(
            "Attacker at 192.168.1.100 exploits this",
            tokenize_ips=True
        )
        assert "192.168.1.100" not in result
        assert "[IP]" in result

    def test_replaces_versions(self, cleaner):
        result = cleaner.full_clean(
            "Affects Apache 2.4.51 and earlier",
            tokenize_versions=True
        )
        assert "2.4.51" not in result
        assert "[VERSION]" in result

    def test_normalizes_cve_id_to_uppercase(self, cleaner):
        result = cleaner.full_clean("cve-2021-44228 is critical")
        assert "CVE-2021-44228" in result
        assert "cve-2021-44228" not in result

    def test_decodes_html_entities(self, cleaner):
        result = cleaner.full_clean("SQL &amp; injection via &lt;input&gt;")
        assert "&amp;" not in result
        assert "&lt;" not in result

    def test_normalizes_whitespace(self, cleaner):
        result = cleaner.full_clean("too    many   spaces  here")
        assert "  " not in result

    def test_empty_string_returns_empty(self, cleaner):
        assert cleaner.full_clean("") == ""

    def test_none_returns_empty(self, cleaner):
        assert cleaner.full_clean(None) == ""

    def test_batch_clean_processes_all(self, cleaner):
        texts = [
            "<b>CVE-2021-44228</b>",
            "SQL injection via https://example.com",
            "Affects version 1.2.3",
        ]
        results = cleaner.batch_clean(texts)
        assert len(results) == 3
        assert "<b>" not in results[0]
        assert "https://" not in results[1]

    def test_real_cve_description(self, cleaner):
        text = (
            "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features "
            "do not protect against attacker controlled LDAP endpoints. "
            "See https://logging.apache.org for details. "
            "Attacker IP: 10.0.0.1"
        )
        result = cleaner.full_clean(text)
        assert len(result) > 30
        assert "https://" not in result
        assert "10.0.0.1" not in result
