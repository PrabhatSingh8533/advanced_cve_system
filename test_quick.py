import sys
sys.path.insert(0, "/app")
from app.db.base import Base
from app.db.models.cwe import CWE
from app.db.models.cve import CVE
from app.services.ml.severity.predictor import CVESSeverityPredictor

pred = CVESSeverityPredictor()
print("Trained:", pred.is_trained())
print()

tests = [
    ("unauthenticated remote code execution via JNDI complete system compromise", "CRITICAL"),
    ("SQL injection authentication bypass high severity database extraction", "HIGH"),
    ("cross-site scripting requires user interaction medium severity", "MEDIUM"),
    ("minor information disclosure local access only no exploitation", "LOW"),
]

correct = 0
for text, expected in tests:
    try:
        r = pred.predict_ensemble(text)
        ok = r["severity"] == expected
        if ok:
            correct += 1
        icon = "OK " if ok else "NO "
        cl  = r.get("components", {}).get("classical", "N/A")
        tr  = r.get("components", {}).get("transformer", "N/A")
        print(icon + "Expected=" + expected + " Got=" + r["severity"] + " Score=" + str(r["cvss_score"]) + " (CL=" + str(cl) + " TR=" + str(tr) + ")")
    except Exception as e:
        print("ERR Expected=" + expected + " Error=" + str(e))

print()
print("Result: " + str(correct) + "/4 correct")