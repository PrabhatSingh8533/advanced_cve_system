"""
Severity Feature Extractor - Memory Optimized.
"""

import re
import pickle
import numpy as np
from pathlib import Path
from loguru import logger
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler


class CVESeverityFeatureExtractor:
    """Memory-optimized feature extractor."""

    CRITICAL_KEYWORDS = [
        "remote code execution", "rce", "arbitrary code",
        "unauthenticated", "wormable", "zero-click",
        "complete system", "full control"
    ]
    HIGH_KEYWORDS = [
        "privilege escalation", "authentication bypass",
        "sql injection", "buffer overflow", "heap overflow",
        "root access", "admin access", "credentials"
    ]
    MEDIUM_KEYWORDS = [
        "cross-site scripting", "xss", "csrf",
        "path traversal", "information disclosure",
        "user interaction", "authenticated"
    ]
    LOW_KEYWORDS = [
        "denial of service", "crash", "minor",
        "limited", "low impact", "physical access"
    ]
    NETWORK_KEYWORDS = ["remote", "network", "http", "api"]
    LOCAL_KEYWORDS = ["local", "physical", "adjacent"]

    def __init__(self, model_dir: str = "app/models/severity"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Reduced features for memory efficiency
        self.tfidf = TfidfVectorizer(
            max_features=1000,  # Reduced from 3000
            ngram_range=(1, 2),
            min_df=2,
            sublinear_tf=True,
            strip_accents="unicode"
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def _keyword_features(self, text: str) -> np.ndarray:
        """Extract keyword-based features."""
        tl = text.lower()
        return np.array([
            sum(1 for kw in self.CRITICAL_KEYWORDS if kw in tl),
            sum(1 for kw in self.HIGH_KEYWORDS if kw in tl),
            sum(1 for kw in self.MEDIUM_KEYWORDS if kw in tl),
            sum(1 for kw in self.LOW_KEYWORDS if kw in tl),
            sum(1 for kw in self.NETWORK_KEYWORDS if kw in tl),
            sum(1 for kw in self.LOCAL_KEYWORDS if kw in tl),
            len(text),
            len(text.split()),
            1 if "unauthenticated" in tl else 0,
            1 if "remote" in tl else 0,
            1 if "arbitrary" in tl else 0,
            1 if "execute" in tl else 0,
            1 if re.search(r"CVE-\d{4}-\d+", text) else 0,
        ], dtype=np.float32)

    def fit_transform(self, texts: list) -> np.ndarray:
        """Fit and transform texts."""
        logger.info(f"Fitting on {len(texts)} texts...")
        tfidf_feat = self.tfidf.fit_transform(texts).toarray()
        kw_feat = np.vstack([
            self._keyword_features(t) for t in texts
        ])
        combined = np.hstack([tfidf_feat, kw_feat])
        self.scaler.fit(combined)
        self.is_fitted = True
        logger.info(f"Feature shape: {combined.shape}")
        return self.scaler.transform(combined)

    def transform(self, texts: list) -> np.ndarray:
        """Transform texts."""
        if not self.is_fitted:
            raise RuntimeError("Fit extractor first!")
        tfidf_feat = self.tfidf.transform(texts).toarray()
        kw_feat = np.vstack([
            self._keyword_features(t) for t in texts
        ])
        return self.scaler.transform(
            np.hstack([tfidf_feat, kw_feat])
        )

    def transform_single(self, text: str) -> np.ndarray:
        """Transform single text."""
        return self.transform([text])

    def save(self):
        """Save extractor."""
        with open(
            self.model_dir / "feature_extractor.pkl", "wb"
        ) as f:
            pickle.dump({
                "tfidf": self.tfidf,
                "scaler": self.scaler,
                "is_fitted": self.is_fitted
            }, f)
        logger.info("Feature extractor saved")

    def load(self):
        """Load extractor."""
        path = self.model_dir / "feature_extractor.pkl"
        if not path.exists():
            raise FileNotFoundError(
                "Extractor not found. Train first."
            )
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.tfidf = data["tfidf"]
        self.scaler = data["scaler"]
        self.is_fitted = data["is_fitted"]
        logger.info("Feature extractor loaded")
