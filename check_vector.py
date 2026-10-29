import sys
sys.path.insert(0, "/app")
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.db.session import SessionLocal

db = SessionLocal()

# Check if CVEs have vector strings stored
print("=== Checking CVSS Vector Data ===")
sample = db.query(CVE).filter(
    CVE.cvss_score.isnot(None),
    CVE.cvss_score > 0
).limit(5).all()

for cve in sample:
    print("CVE:", cve.cve_id, "Score:", cve.cvss_score)
    print("Severity:", cve.severity)
    print("All fields:", [c.name for c in CVE.__table__.columns])
    break

db.close()