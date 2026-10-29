"""Integration Tests for Analytics & NLP APIs."""

import pytest


class TestAnalytics:

    def test_summary_200(self, client):
        r = client.get("/api/analytics/summary")
        assert r.status_code == 200

    def test_summary_structure(self, client):
        r = client.get("/api/analytics/summary")
        data = r.json()
        assert "total_cves_analyzed" in data
        assert "date_range" in data

    def test_rce_returns_200(self, client):
        r = client.get("/api/analytics/rce")
        assert r.status_code == 200

    def test_rce_has_chart(self, client):
        r = client.get("/api/analytics/rce")
        data = r.json()
        assert "total_rce_cves" in data
        assert "chart" in data
        assert "data" in data["chart"]

    def test_os_returns_200(self, client):
        r = client.get("/api/analytics/os")
        assert r.status_code == 200

    def test_os_has_platforms(self, client):
        r = client.get("/api/analytics/os")
        data = r.json()
        assert "top_platforms" in data
        assert len(data["top_platforms"]) > 0

    def test_forecast_returns_200(self, client):
        r = client.get("/api/analytics/forecast?steps=6")
        assert r.status_code == 200

    def test_forecast_structure(self, client):
        r = client.get("/api/analytics/forecast?steps=6")
        data = r.json()
        assert "forecast_period" in data
        assert "arima_forecast" in data
        assert "dates" in data["arima_forecast"]

    def test_forecast_invalid_steps(self, client):
        r = client.get("/api/analytics/forecast?steps=100")
        assert r.status_code == 422

    def test_monthly_chart_returns_200(self, client):
        r = client.get("/api/analytics/charts/monthly")
        assert r.status_code == 200
        assert "data" in r.json()

    def test_heatmap_returns_200(self, client):
        r = client.get("/api/analytics/heatmap")
        assert r.status_code == 200


class TestCollection:

    def test_status_returns_200(self, client):
        r = client.get("/api/collect/status")
        assert r.status_code == 200

    def test_status_structure(self, client):
        r = client.get("/api/collect/status")
        data = r.json()
        assert "database" in data
        assert "total_cves" in data["database"]

    def test_invalid_year_returns_400(self, client):
        r = client.post("/api/collect/year/1800")
        assert r.status_code == 400

    def test_invalid_days_returns_400(self, client):
        r = client.post("/api/collect/recent?days=0")
        assert r.status_code == 422


class TestNLP:

    def test_health_returns_200(self, client):
        r = client.get("/api/nlp/health")
        assert r.status_code == 200

    def test_tokenize_returns_tokens(self, client):
        r = client.post(
            "/api/nlp/tokenize",
            json={"text": "SQL injection vulnerability in login form"}
        )
        assert r.status_code == 200
        data = r.json()
        assert "tokens" in data
        assert "count" in data
        assert data["count"] > 0

    def test_entities_returns_dict(self, client):
        r = client.post(
            "/api/nlp/entities",
            json={"text": "CVE-2021-44228 Apache Log4j RCE vulnerability"}
        )
        assert r.status_code == 200
        data = r.json()
        assert "entities" in data
        assert "cve_ids" in data["entities"]

    def test_empty_text_returns_400(self, client):
        r = client.post(
            "/api/nlp/tokenize",
            json={"text": ""}
        )
        assert r.status_code == 400

    def test_analyze_returns_full_result(self, client):
        r = client.post(
            "/api/nlp/analyze",
            json={"text": "Remote code execution via buffer overflow in Apache"}
        )
        assert r.status_code == 200
        data = r.json()
        assert "tokens" in data
        assert "entities" in data


class TestBERT:

    def test_status_returns_200(self, client):
        r = client.get("/api/bert/status")
        assert r.status_code == 200

    def test_status_has_fields(self, client):
        r = client.get("/api/bert/status")
        data = r.json()
        assert "real_model_trained" in data
        assert "model" in data

    def test_labels_returns_200(self, client):
        r = client.get("/api/bert/labels")
        assert r.status_code == 200

    def test_data_report_returns_200(self, client):
        r = client.get("/api/bert/data-report")
        assert r.status_code == 200


class TestSeverity:

    def test_status_returns_200(self, client):
        r = client.get("/api/severity/status")
        assert r.status_code == 200

    def test_status_has_fields(self, client):
        r = client.get("/api/severity/status")
        data = r.json()
        assert "models_trained" in data
        assert "status" in data
