"""Prediction Pydantic Schemas."""

from pydantic import BaseModel
from typing import Optional, Dict


class PredictionRequest(BaseModel):
    """Request schema for all predictions."""
    text: str
    include_all_scores: bool = True


class ExploitPredictionResponse(BaseModel):
    """BERT exploit type prediction response."""
    predicted_label: str
    confidence: float
    all_probabilities: Dict[str, float]
    model_used: str = "distilbert-base-uncased"


class SeverityPredictionResponse(BaseModel):
    """CVSS severity prediction response."""
    cvss_score: float
    severity: str
    method: str
    components: Optional[Dict] = None


class FullAnalysisResponse(BaseModel):
    """Complete CVE analysis response."""
    text: str
    clean_text: str
    exploit_prediction: Optional[dict] = None
    severity_prediction: Optional[dict] = None
    entities: Optional[dict] = None
    tokens: Optional[list] = None
