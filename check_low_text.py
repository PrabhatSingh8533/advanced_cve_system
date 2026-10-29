import sys
sys.path.insert(0, "/app")
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.db.session import SessionLocal

db = SessionLocal()

print("=== LOW CVEs (score < 4.0) - What do they say? ===")
lows = db.query(CVE).filter(
    CVE.cvss_score < 4.0,
    CVE.cvss_score > 0,
    CVE.description.isnot(None)
).limit(10).all()

for cve in lows:
    print()
    print("CVE:", cve.cve_id, "| Score:", cve.cvss_score)
    print("Text:", cve.description[:250])
    print("-" * 60)

print()
print("=== CRITICAL CVEs (score >= 9.0) - failing ones ===")
crits = db.query(CVE).filter(
    CVE.cvss_score >= 9.0,
    CVE.description.isnot(None)
).limit(5).all()

for cve in crits:
    print()
    print("CVE:", cve.cve_id, "| Score:", cve.cvss_score)
    print("Text:", cve.description[:250])
    print("-" * 60)

db.close()