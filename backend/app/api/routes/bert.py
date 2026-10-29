"""BERT API Endpoints - Local Version."""

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from loguru import logger
from app.db.session import get_db

router = APIRouter(prefix="/api/bert", tags=["BERT Model"])

_training_status = {
    "status": "idle",
    "progress": "",
    "error": None
}


def get_trainer():
    from app.services.ml.real_bert_trainer import RealDataBERTTrainer
    return RealDataBERTTrainer()


class TrainRequest(BaseModel):
    epochs: int = 3
    min_samples_per_class: int = 20
    use_db_data: bool = True


@router.get("/status")
def get_status():
    """Check BERT model status."""
    import json
    from pathlib import Path

    model_path = Path("app/models/bert_real/cve_classifier_real")
    trained = model_path.exists() and any(model_path.iterdir())

    results = {}
    rp = Path("app/models/bert_real/real_training_results.json")
    if rp.exists():
        with open(rp) as f:
            results = json.load(f)

    return {
        "real_model_trained": trained,
        "model": "distilbert-base-uncased",
        "training_status": _training_status,
        "metrics": {
            "test_f1_macro": results.get("test_f1_macro"),
            "test_accuracy": results.get("test_accuracy"),
            "training_samples": results.get("training_samples"),
            "num_classes": results.get("num_classes"),
        } if results else {}
    }


@router.get("/data-report")
def data_report(db: Session = Depends(get_db)):
    """Show available training data."""
    from app.services.ml.real_data_labeler import RealTrainingDataBuilder
    builder = RealTrainingDataBuilder(db)
    return builder.get_dataset_report()


@router.get("/labels")
def get_labels():
    """Get exploit type labels."""
    from app.services.ml.real_data_labeler import RealCVELabeler
    labeler = RealCVELabeler()
    return {
        "exploit_types": list(set(labeler.CWE_TO_EXPLOIT.values())),
        "total": len(set(labeler.CWE_TO_EXPLOIT.values()))
    }


@router.post("/train-real")
def train_real(
    request: TrainRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Train BERT on real NVD data."""
    global _training_status
    _training_status = {
        "status": "starting",
        "progress": "Initializing...",
        "error": None
    }

    def run():
        global _training_status
        from app.db.session import SessionLocal
        db_s = SessionLocal()
        try:
            from app.services.ml.real_data_labeler import (
                RealTrainingDataBuilder
            )
            _training_status["progress"] = "Labeling CVEs..."
            builder = RealTrainingDataBuilder(db_s)
            data = builder.build_classification_dataset(
                min_samples_per_class=request.min_samples_per_class
            )

            if "error" in data:
                _training_status["status"] = "failed"
                _training_status["error"] = data["error"]
                return

            _training_status["progress"] = (
                f"Training on {data['total_samples']} CVEs..."
            )
            _training_status["status"] = "training"

            trainer = get_trainer()
            results = trainer.train(
                dataset=data["dataset"],
                label_map=data["label_map"],
                epochs=request.epochs
            )

            _training_status = {
                "status": "completed",
                "progress": "Done!",
                "error": None,
                "f1": results.get("test_f1_macro")
            }
            logger.success(
                f"Training done! F1={results.get('test_f1_macro')}"
            )
        except Exception as e:
            logger.error(f"Training error: {e}", exc_info=True)
            _training_status = {
                "status": "failed",
                "progress": str(e),
                "error": str(e)
            }
        finally:
            db_s.close()

    background_tasks.add_task(run)
    return {
        "message": "Training started in background",
        "tip": "GET /api/bert/status to check progress"
    }


@router.post("/predict-real")
def predict_real(text: str):
    """Predict exploit type from CVE description."""
    if not text or not text.strip():
        raise HTTPException(400, "Text cannot be empty")

    from pathlib import Path
    model_path = Path("app/models/bert_real/cve_classifier_real")

    if not model_path.exists():
        raise HTTPException(
            400,
            "Model not trained. POST /api/bert/train-real first."
        )

    try:
        trainer = get_trainer()
        result = trainer.predict(text)
        return {"prediction": result}
    except FileNotFoundError:
        raise HTTPException(
            400,
            "Model not trained. POST /api/bert/train-real first."
        )
    except Exception as e:
        logger.error(f"Predict error: {e}")
        raise HTTPException(500, str(e))


@router.post("/evaluate")
def evaluate():
    """Quick evaluation on test cases."""
    from pathlib import Path
    if not Path("app/models/bert_real/cve_classifier_real").exists():
        raise HTTPException(400, "Train model first.")

    tests = [
        ("Apache Log4j2 remote code execution via JNDI injection", "Remote Code Execution"),
        ("SQL injection in login form allows database extraction", "SQL Injection"),
        ("Cross-site scripting via search parameter", "Cross-Site Scripting"),
        ("Buffer overflow in image parser allows code execution", "Buffer Overflow"),
        ("Denial of service via malformed HTTP request", "Denial of Service"),
    ]

    trainer = get_trainer()
    results = []
    correct = 0

    for text, expected in tests:
        try:
            pred = trainer.predict(text)
            is_correct = pred["predicted_label"] == expected
            if is_correct:
                correct += 1
            results.append({
                "text": text[:80],
                "expected": expected,
                "predicted": pred["predicted_label"],
                "confidence": pred["confidence"],
                "correct": is_correct
            })
        except Exception as e:
            results.append({"text": text[:80], "error": str(e)})

    return {
        "accuracy": round(correct / len(tests), 4),
        "correct": correct,
        "total": len(tests),
        "results": results
    }
