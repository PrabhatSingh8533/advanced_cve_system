"""BERT Inference Service."""
import json
from pathlib import Path
from loguru import logger
from app.services.ml.bert_trainer import CVEBERTTrainer


class CVEBERTInference:
    _instance = None
    _model = None
    _tokenizer = None
    _label_map = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._trainer = CVEBERTTrainer()
        logger.info("BERTInference ready")

    def is_model_trained(self) -> bool:
        path = Path("app/models/bert/cve_classifier")
        return path.exists() and any(path.iterdir())

    def get_history(self) -> list:
        path = Path("app/models/bert/history.json")
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return []

    def _load_if_needed(self):
        if self._model is None:
            if not self.is_model_trained():
                raise RuntimeError("No model. Train first.")
            self._model, self._tokenizer, self._label_map = (
                self._trainer.load_classifier()
            )

    def predict(self, text: str) -> dict:
        self._load_if_needed()
        return self._trainer.predict_exploit_type(
            text,
            model=self._model,
            tokenizer=self._tokenizer,
            label_map=self._label_map
        )

    def train(
        self,
        epochs: int = 5,
        batch_size: int = 16,
        samples_per_class: int = 60,
        db=None
    ) -> dict:
        self._model = None
        self._tokenizer = None
        self._label_map = None
        results = self._trainer.train_classifier(
            epochs=epochs,
            batch_size=batch_size,
            samples_per_class=samples_per_class,
            db=db
        )
        self._load_if_needed()
        return results
