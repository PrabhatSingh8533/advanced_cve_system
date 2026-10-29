"""Unit Tests for Real CVE Data Labeler."""

import pytest
from app.services.ml.real_data_labeler import RealCVELabeler


@pytest.fixture(scope="module")
def labeler():
    return RealCVELabeler()


class TestRealCVELabeler:

    def test_cwe89_maps_to_sqli(self, labeler):
        exploit, conf, source = labeler.label_exploit_type(
            "Any text", "CWE-89"
        )
        assert exploit == "SQL Injection"
        assert conf >= 0.9
        assert source == "cwe_mapping"

    def test_cwe79_maps_to_xss(self, labeler):
        exploit, conf, source = labeler.label_exploit_type(
            "Any text", "CWE-79"
        )
        assert exploit == "Cross-Site Scripting"
        assert source == "cwe_mapping"

    def test_cwe787_maps_to_buffer_overflow(self, labeler):
        exploit, conf, source = labeler.label_exploit_type(
            "Any text", "CWE-787"
        )
        assert exploit == "Buffer Overflow"

    def test_rce_keyword_detected(self, labeler):
        desc = "allows remote code execution via JNDI injection"
        exploit, conf, source = labeler.label_exploit_type(desc)
        assert exploit == "Remote Code Execution"
        assert source == "keyword_match"

    def test_sqli_keyword_detected(self, labeler):
        desc = "SQL injection vulnerability via username parameter"
        exploit, conf, source = labeler.label_exploit_type(desc)
        assert exploit == "SQL Injection"

    def test_unknown_returns_none(self, labeler):
        desc = "A software update improves performance"
        exploit, conf, source = labeler.label_exploit_type(desc)
        assert exploit is None
        assert conf == 0.0
        assert source == "unlabeled"

    def test_cwe_priority_over_keywords(self, labeler):
        desc = "remote code execution via SQL injection"
        exploit, conf, source = labeler.label_exploit_type(
            desc, "CWE-89"
        )
        assert exploit == "SQL Injection"
        assert source == "cwe_mapping"

    def test_valid_description_suitable(self, labeler):
        record = {
            "description": (
                "SQL injection allows remote attackers to bypass "
                "authentication via crafted input parameter."
            )
        }
        assert labeler.is_suitable_for_training(record) is True

    def test_short_description_not_suitable(self, labeler):
        record = {"description": "Bug fix"}
        assert labeler.is_suitable_for_training(record) is False

    def test_reserved_cve_not_suitable(self, labeler):
        record = {
            "description": "** RESERVED ** This candidate has been reserved."
        }
        assert labeler.is_suitable_for_training(record) is False

    def test_all_important_cwes_mapped(self, labeler):
        important_cwes = [
            "CWE-79", "CWE-89", "CWE-94",
            "CWE-119", "CWE-287", "CWE-22",
            "CWE-400", "CWE-269"
        ]
        for cwe in important_cwes:
            assert cwe in labeler.CWE_TO_EXPLOIT, \
                f"{cwe} not in CWE mapping!"
