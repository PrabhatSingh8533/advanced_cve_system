import sys
sys.path.insert(0, "/app")
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.db.session import SessionLocal
from sqlalchemy import func

db = SessionLocal()

print("=== CWE vs CVSS Score Analysis ===")
results = db.query(
    CWE.cwe_code,
    func.count(CVE.id).label("count"),
    func.avg(CVE.cvss_score).label("avg_score"),
    func.min(CVE.cvss_score).label("min_score"),
    func.max(CVE.cvss_score).label("max_score")
).join(CVE, CVE.cwe_id == CWE.id).filter(
    CVE.cvss_score.isnot(None),
    CVE.cvss_score > 0
).group_by(CWE.cwe_code).order_by(
    func.count(CVE.id).desc()
).limit(15).all()

print("CWE Code   | Count | Avg Score | Typical Severity")
print("-" * 60)
for r in results:
    avg = round(float(r.avg_score), 1)
    if avg >= 9.0:   typ = "CRITICAL"
    elif avg >= 7.0: typ = "HIGH"
    elif avg >= 4.0: typ = "MEDIUM"
    else:            typ = "LOW"
    print(f"{r.cwe_code:<12} {r.count:<7} {avg:<10} {typ}")

db.close()