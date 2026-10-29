import json
import os

# Check what real CVSS data we have
import sys
sys.path.insert(0, "/app")

from app.db.session import SessionLocal
from app.db.models.cve import CVE, CWE
from sqlalchemy import func

db = SessionLocal()

total = db.query(CVE).count()
with_cvss = db.query(CVE).filter(
    CVE.cvss_score.isnot(None),
    CVE.cvss_score > 0
).count()
with_sev = db.query(CVE).filter(
    CVE.severity.isnot(None)
).count()

print(f"Total CVEs: {total}")
print(f"With CVSS score: {with_cvss}")
print(f"With severity: {with_sev}")

# Sample some CVSS scores
samples = db.query(CVE.cvss_score, CVE.severity).filter(
    CVE.cvss_score.isnot(None),
    CVE.cvss_score > 0
).limit(10).all()

print("\nSample CVSS scores:")
for s in samples:
    print(f"  Score={s.cvss_score} Severity={s.severity}")

db.close()