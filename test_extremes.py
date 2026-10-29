import sys
sys.path.insert(0, "/app")
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.db.session import SessionLocal

db = SessionLocal()

# Test known CRITICAL CVEs from DB
print("=== Testing Real CRITICAL CVEs ===")
criticals = db.query(CVE).filter(
    CVE.cvss_score >= 9.0,
    CVE.description.isnot(None),
    CVE.description != ""
).limit(10).all()

print(f"Testing {len(criticals)} CRITICAL CVEs (score >= 9.0)")
print()

from app.services.ml.severity.predictor import CVESSeverityPredictor
pred = CVESSeverityPredictor()

correct_c = 0
for cve in criticals:
    try:
        result = pred.predict_ensemble(cve.description[:300])
        score = result["cvss_score"]
        sev = result["severity"]
        correct = sev == "CRITICAL"
        if correct: correct_c += 1
        icon = "✅" if correct else "❌"
        print(f"{icon} True={cve.cvss_score} Pred={score}({sev}) | {cve.cve_id}")
    except Exception as e:
        print(f"Error: {e}")

print(f"\nCRITICAL Accuracy: {correct_c}/{len(criticals)}")

# Test LOW CVEs
print("\n=== Testing Real LOW CVEs ===")
lows = db.query(CVE).filter(
    CVE.cvss_score < 4.0,
    CVE.cvss_score > 0,
    CVE.description.isnot(None),
    CVE.description != ""
).limit(10).all()

print(f"Testing {len(lows)} LOW CVEs (score < 4.0)")
print()

correct_l = 0
for cve in lows:
    try:
        result = pred.predict_ensemble(cve.description[:300])
        score = result["cvss_score"]
        sev = result["severity"]
        correct = sev == "LOW"
        if correct: correct_l += 1
        icon = "✅" if correct else "❌"
        print(f"{icon} True={cve.cvss_score} Pred={score}({sev}) | {cve.cve_id}")
    except Exception as e:
        print(f"Error: {e}")

print(f"\nLOW Accuracy: {correct_l}/{len(lows)}")
db.close()