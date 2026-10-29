"""
Pytest Configuration & Shared Fixtures.
Uses SQLite in-memory DB for fast testing.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import date

from app.db.base import Base
from app.db.session import get_db
from app.db.models.cve import CVE
from app.db.models.cwe import CWE
from app.main import app

# ── Test Database ─────────────────────────────────────────
TEST_DB_URL = "sqlite:///./test_cve.db"

engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False}
)
TestingSession = sessionmaker(
    autocommit=False, autoflush=False, bind=engine
)


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Create tables once per test session."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    import os
    if os.path.exists("test_cve.db"):
        os.remove("test_cve.db")


@pytest.fixture
def db():
    """Fresh DB session per test."""
    db = TestingSession()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


@pytest.fixture
def client():
    """Test client with test DB."""
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def sample_cwe(db):
    """Sample CWE record."""
    cwe = CWE(cwe_code="CWE-89", name="SQL Injection")
    db.add(cwe)
    db.commit()
    db.refresh(cwe)
    yield cwe
    try:
        db.delete(cwe)
        db.commit()
    except Exception:
        db.rollback()


@pytest.fixture
def sample_cve(db, sample_cwe):
    """Sample CVE record."""
    cve = CVE(
        cve_id="CVE-2021-99999",
        description=(
            "SQL injection vulnerability allows remote attackers "
            "to bypass authentication via crafted username parameter."
        ),
        published_date=date(2021, 12, 10),
        cvss_score=9.8,
        severity="CRITICAL",
        exploit_type="SQL Injection",
        cwe_id=sample_cwe.id
    )
    db.add(cve)
    db.commit()
    db.refresh(cve)
    yield cve
    try:
        db.delete(cve)
        db.commit()
    except Exception:
        db.rollback()


@pytest.fixture
def multiple_cves(db, sample_cwe):
    """Multiple CVE records."""
    cves_data = [
        {
            "cve_id": "CVE-2021-10001",
            "description": "Remote code execution via JNDI injection in Apache Log4j2",
            "published_date": date(2021, 12, 1),
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "exploit_type": "Remote Code Execution",
        },
        {
            "cve_id": "CVE-2021-10002",
            "description": "Cross-site scripting via search parameter requires user interaction",
            "published_date": date(2021, 11, 15),
            "cvss_score": 6.1,
            "severity": "MEDIUM",
            "exploit_type": "Cross-Site Scripting",
        },
        {
            "cve_id": "CVE-2021-10003",
            "description": "Denial of service via malformed HTTP packet causes crash",
            "published_date": date(2021, 10, 20),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "exploit_type": "Denial of Service",
        },
        {
            "cve_id": "CVE-2021-10004",
            "description": "Minor information disclosure via verbose error messages",
            "published_date": date(2021, 9, 5),
            "cvss_score": 2.1,
            "severity": "LOW",
            "exploit_type": "Information Disclosure",
        },
    ]

    created = []
    for data in cves_data:
        cve = CVE(cwe_id=sample_cwe.id, **data)
        db.add(cve)
        created.append(cve)

    db.commit()
    for cve in created:
        db.refresh(cve)

    yield created

    for cve in created:
        try:
            db.delete(cve)
        except Exception:
            pass
    try:
        db.commit()
    except Exception:
        db.rollback()
