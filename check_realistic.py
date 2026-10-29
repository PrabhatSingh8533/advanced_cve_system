import sys
sys.path.insert(0, "/app")
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.db.session import SessionLocal

db = SessionLocal()

# Check severity distribution already stored
print("=== Severity Labels Already in DB ===")
from sqlalchemy import func

results = db.query(
    CVE.severity,
    func.count(CVE.id).label("count"),
    func.avg(CVE.cvss_score).label("avg_score"),
    func.min(CVE.cvss_score).label("min_score"),
    func.max(CVE.cvss_score).label("max_score")
).filter(
    CVE.severity.isnot(None),
    CVE.cvss_score.isnot(None)
).group_by(CVE.severity).all()

print("Severity | Count  | Avg Score | Min  | Max")
print("-" * 55)
for r in results:
    print(f"{r.severity:<10} {r.count:<8} {round(float(r.avg_score),2):<10} {round(float(r.min_score),2):<5} {round(float(r.max_score),2)}")

print()
print("Total with severity:", sum(r.count for r in results))

db.close()