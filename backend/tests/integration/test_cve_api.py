"""Integration Tests for CVE API Endpoints."""

import pytest


class TestCVEList:

    def test_returns_200(self, client):
        r = client.get("/api/cves/")
        assert r.status_code == 200

    def test_has_pagination(self, client, multiple_cves):
        r = client.get("/api/cves/?page=1&page_size=10")
        data = r.json()
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "total_pages" in data
        assert "items" in data

    def test_filter_by_severity(self, client, multiple_cves):
        r = client.get("/api/cves/?severity=CRITICAL")
        assert r.status_code == 200
        data = r.json()
        for item in data["items"]:
            assert item["severity"] == "CRITICAL"

    def test_filter_by_min_cvss(self, client, multiple_cves):
        r = client.get("/api/cves/?min_cvss=9.0")
        assert r.status_code == 200
        data = r.json()
        for item in data["items"]:
            if item["cvss_score"]:
                assert item["cvss_score"] >= 9.0

    def test_filter_by_year(self, client, multiple_cves):
        r = client.get("/api/cves/?year=2021")
        assert r.status_code == 200


class TestCVESearch:

    def test_search_keyword(self, client, multiple_cves):
        r = client.get("/api/cves/search?q=injection")
        assert r.status_code == 200
        data = r.json()
        assert "query" in data
        assert data["query"] == "injection"

    def test_search_cve_id(self, client, sample_cve):
        r = client.get(
            f"/api/cves/search?q={sample_cve.cve_id}"
        )
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_search_too_short_fails(self, client):
        r = client.get("/api/cves/search?q=a")
        assert r.status_code == 422

    def test_search_empty_returns_zero(self, client):
        r = client.get("/api/cves/search?q=xyznonexistent99999")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_search_pagination(self, client, multiple_cves):
        r = client.get(
            "/api/cves/search?q=vulnerability&page=1&page_size=2"
        )
        data = r.json()
        assert "page" in data
        assert "total_pages" in data


class TestCVEGet:

    def test_get_existing_cve(self, client, sample_cve):
        r = client.get(f"/api/cves/{sample_cve.cve_id}")
        assert r.status_code == 200
        assert r.json()["cve_id"] == sample_cve.cve_id

    def test_get_nonexistent_returns_404(self, client):
        r = client.get("/api/cves/CVE-9999-99999")
        assert r.status_code == 404

    def test_get_lowercase_id_works(self, client, sample_cve):
        lower = sample_cve.cve_id.lower()
        r = client.get(f"/api/cves/{lower}")
        assert r.status_code == 200

    def test_response_has_correct_fields(self, client, sample_cve):
        r = client.get(f"/api/cves/{sample_cve.cve_id}")
        data = r.json()
        assert "cve_id" in data
        assert "description" in data
        assert "cvss_score" in data
        assert "severity" in data


class TestCVEStats:

    def test_stats_returns_200(self, client):
        r = client.get("/api/cves/stats")
        assert r.status_code == 200

    def test_stats_with_data(self, client, multiple_cves):
        r = client.get("/api/cves/stats")
        data = r.json()
        assert "total_cves" in data
        if data["total_cves"] > 0:
            assert "severity_distribution" in data
            assert "top_exploit_types" in data
            assert "average_cvss_score" in data

    def test_severity_keys_present(self, client, multiple_cves):
        r = client.get("/api/cves/stats")
        data = r.json()
        if data.get("severity_distribution"):
            sev = data["severity_distribution"]
            for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                assert key in sev


class TestCVERecent:

    def test_recent_returns_200(self, client):
        r = client.get("/api/cves/recent?days=7")
        assert r.status_code == 200

    def test_recent_has_structure(self, client):
        r = client.get("/api/cves/recent?days=30")
        data = r.json()
        assert "days" in data
        assert "count" in data
        assert "items" in data

    def test_recent_invalid_days(self, client):
        r = client.get("/api/cves/recent?days=999")
        assert r.status_code == 422


class TestSystem:

    def test_root_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "name" in r.json()

    def test_health_returns_healthy(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    def test_routes_lists_endpoints(self, client):
        r = client.get("/routes")
        assert r.status_code == 200
        data = r.json()
        assert "total_routes" in data
        assert data["total_routes"] > 5
