"""NLP API endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from loguru import logger
from app.db.session import get_db

router = APIRouter(prefix="/api/nlp", tags=["NLP Processing"])

_pipeline = None

def get_pipeline():
    global _pipeline
    if _pipeline is None:
        from app.services.nlp.pipeline import CVENLPPipeline
        _pipeline = CVENLPPipeline()
        logger.info("NLP Pipeline initialized")
    return _pipeline


class TextInput(BaseModel):
    text: str


@router.get("/health")
def nlp_health():
    return {"status": "NLP routes active"}


@router.post("/analyze")
def analyze_cve_text(payload: TextInput):
    if not payload.text.strip():
        raise HTTPException(400, "Text cannot be empty")
    return get_pipeline().process(payload.text)


@router.post("/entities")
def extract_entities(payload: TextInput):
    if not payload.text.strip():
        raise HTTPException(400, "Text cannot be empty")
    p = get_pipeline()
    clean = p.cleaner.full_clean(payload.text)
    return {"entities": p.ner.extract_all(clean)}


@router.post("/tokenize")
def tokenize_text(payload: TextInput):
    p = get_pipeline()
    clean = p.cleaner.full_clean(payload.text)
    tokens = p.tokenizer.tokenize(clean)
    return {"clean_text": clean, "tokens": tokens, "count": len(tokens)}


@router.post("/build-vocabulary")
def build_vocabulary(db: Session = Depends(get_db)):
    p = get_pipeline()
    vocab = p.build_vocabulary_from_db(db)
    return {"message": "Done", "vocab_size": len(vocab)}
