import sys
sys.path.insert(0, "/app")
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.db.session import SessionLocal

db = SessionLocal()

# See actual text of LOW CVEs that failed
print("=== LOW CVEs Text Analysis ===")
lows = db.query(CVE).filter(
    CVE.cvss_score < 4.0,
    CVE.cvss_score > 0,
    CVE.description.isnot(None)
).limit(20).all()

for cve in lows:
    score = float(cve.cvss_score)
    desc  = cve.description[:200]
    print(f"\nCVSS={score} | {cve.cve_id}")
    print(f"Text: {desc}")

db.close()