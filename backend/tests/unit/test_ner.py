"""Unit Tests for Named Entity Recognition."""

import pytest
from app.services.nlp.ner import CVEEntityExtractor


@pytest.fixture(scope="module")
def extractor():
    return CVEEntityExtractor()


class TestCVEEntityExtractor:

    def test_extracts_cve_id(self, extractor):
        ids = extractor.extract_cve_ids(
            "CVE-2021-44228 is a critical log4j vulnerability"
        )
        assert "CVE-2021-44228" in ids

    def test_extracts_multiple_cve_ids(self, extractor):
        ids = extractor.extract_cve_ids(
            "CVE-2021-44228 and CVE-2021-45046 both affect Log4j"
        )
        assert len(ids) == 2

    def test_extracts_cwe_id(self, extractor):
        cwes = extractor.extract_cwe_ids(
            "This is classified as CWE-89 SQL Injection"
        )
        assert "CWE-89" in cwes

    def test_detects_rce(self, extractor):
        attacks = extractor.extract_attack_types(
            "allows remote code execution via JNDI injection"
        )
        assert "RCE" in attacks

    def test_detects_sqli(self, extractor):
        attacks = extractor.extract_attack_types(
            "SQL injection vulnerability in login form"
        )
        assert "SQLi" in attacks

    def test_detects_xss(self, extractor):
        attacks = extractor.extract_attack_types(
            "cross-site scripting via search parameter"
        )
        assert "XSS" in attacks

    def test_detects_buffer_overflow(self, extractor):
        attacks = extractor.extract_attack_types(
            "heap-based buffer overflow in image parser"
        )
        assert "Buffer_Overflow" in attacks

    def test_detects_dos(self, extractor):
        attacks = extractor.extract_attack_types(
            "denial of service via malformed request"
        )
        assert "DoS" in attacks

    def test_detects_critical_severity(self, extractor):
        sev = extractor.extract_severity_indicator(
            "critical vulnerability allows complete compromise"
        )
        assert sev == "CRITICAL"

    def test_no_attack_generic_text(self, extractor):
        attacks = extractor.extract_attack_types(
            "This is a software update with performance improvements"
        )
        assert len(attacks) == 0

    def test_extract_all_returns_dict(self, extractor):
        result = extractor.extract_all(
            "CVE-2021-44228: Apache Log4j2 remote code execution"
        )
        assert isinstance(result, dict)
        assert "cve_ids" in result
        assert "attack_types" in result
        assert "software_entities" in result

    def test_extracts_cvss_score(self, extractor):
        scores = extractor.extract_cvss_scores(
            "CVSS score: 9.8 critical severity"
        )
        assert 9.8 in scores

    def test_empty_text_returns_empty(self, extractor):
        result = extractor.extract_all("")
        assert result["cve_ids"] == []
        assert result["attack_types"] == []
