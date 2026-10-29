import sys
sys.path.insert(0, "/app")
import pickle
import numpy as np

with open("app/models/severity/feature_extractor.pkl", "rb") as f:
    fe = pickle.load(f)

tfidf  = fe["tfidf"]
scaler = fe["scaler"]

print("TF-IDF features:", tfidf.max_features)
print("Scaler expects:", scaler.n_features_in_)
print("TF-IDF vocab size:", len(tfidf.vocabulary_))

# Calculate keyword features count
kw_count = scaler.n_features_in_ - len(tfidf.vocabulary_)
print("Keyword features:", kw_count)