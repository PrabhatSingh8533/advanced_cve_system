"""Severity Prediction API Endpoints."""

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from loguru import logger
from app.db.session import get_db

router = APIRouter(prefix="/api/severity", tags=["Severity Prediction"])

_predictor = None


def get_predictor():
    global _predictor
    if _predictor is None:
        from app.services.ml.severity.predictor import CVESSeverityPredictor
        _predictor = CVESSeverityPredictor()
    return _predictor


class PredictRequest(BaseModel):
    text: str
    method: str = "ensemble"  # classical, transformer, ensemble


class TrainRequest(BaseModel):
    samples_per_severity: int = 150
    epochs: int = 5
    use_db_data: bool = False


@router.get("/status")
def get_status():
    """Check if severity models are trained."""
    pred = get_predictor()
    trained = pred.is_trained()

    results = {}
    if trained:
        import json
        from pathlib import Path
        results_path = Path("app/models/severity/training_results.json")
        if results_path.exists():
            with open(results_path) as f:
                results = json.load(f)

    return {
        "models_trained": trained,
        "status": "ready" if trained else "not_trained",
        "available_methods": ["classical", "transformer", "ensemble"],
        "training_results": results.get("comparison", {})
    }


@router.post("/train")
def train_models(
    request: TrainRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Train severity prediction models."""
    pred = get_predictor()

    def run():
        try:
            db_arg = db if request.use_db_data else None
            results = pred.train_all(
                samples_per_severity=request.samples_per_severity,
                epochs=request.epochs,
                db=db_arg
            )
            logger.success("Severity training complete!")
        except Exception as e:
            logger.error(f"Training error: {e}", exc_info=True)

    background_tasks.add_task(run)
    return {
        "message": "Severity training started",
        "settings": request.dict(),
        "tip": "docker logs cve_backend -f"
    }


@router.post("/predict")
def predict_severity(request: PredictRequest):
    """Predict CVSS score and severity from CVE description."""
    if not request.text.strip():
        raise HTTPException(400, "Text cannot be empty")

    pred = get_predictor()

    if not pred.is_trained():
        raise HTTPException(
            400,
            "Models not trained. POST /api/severity/train first."
        )

    try:
        method = request.method.lower()

        if method == "classical":
            result = pred.predict_classical(request.text)
        elif method == "transformer":
            result = pred.predict_transformer(request.text)
        else:  # ensemble
            result = pred.predict_ensemble(request.text)

        return {
            "input_text": request.text[:150],
            "prediction": result,
            "severity_scale": {
                "CRITICAL": "9.0 - 10.0",
                "HIGH": "7.0 - 8.9",
                "MEDIUM": "4.0 - 6.9",
                "LOW": "0.1 - 3.9"
            }
        }

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(500, str(e))


@router.post("/compare")
def compare_methods(request: PredictRequest):
    """Compare all prediction methods on same text."""
    if not request.text.strip():
        raise HTTPException(400, "Text cannot be empty")

    pred = get_predictor()

    if not pred.is_trained():
        raise HTTPException(400, "Train models first.")

    results = {}

    try:
        results["classical"] = pred.predict_classical(request.text)
    except Exception as e:
        results["classical"] = {"error": str(e)}

    try:
        results["transformer"] = pred.predict_transformer(request.text)
    except Exception as e:
        results["transformer"] = {"error": str(e)}

    try:
        results["ensemble"] = pred.predict_ensemble(request.text)
    except Exception as e:
        results["ensemble"] = {"error": str(e)}

    return {
        "input_text": request.text[:150],
        "predictions": results
    }


@router.post("/batch")
def batch_predict(texts: list[str]):
    """Predict severity for multiple CVE descriptions."""
    if not texts:
        raise HTTPException(400, "Texts list empty")

    pred = get_predictor()
    if not pred.is_trained():
        raise HTTPException(400, "Train models first.")

    results = []
    for text in texts[:20]:  # limit to 20
        try:
            result = pred.predict_ensemble(text)
            results.append({
                "text": text[:100],
                "prediction": result
            })
        except Exception as e:
            results.append({"text": text[:100], "error": str(e)})

    return {"predictions": results, "count": len(results)}
