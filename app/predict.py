import pandas as pd
import numpy as np
from app.model_loader import model, scaler
from app.feature_extractor import extract_features
from app.heuristic_checks import heuristic_score

# Indices of features whose external data sources are unavailable at inference
# (Alexa, PageRank, Google Index, backlinks, PhishTank).  The extractor
# hard-codes them to 0, but the scaler was trained on real {-1, 0, 1} values.
# Setting them to the scaler's training mean before scaling neutralises them
# (scaled value ≈ 0) so they don't bias the prediction either way.
UNAVAILABLE_FEATURE_INDICES = [25, 26, 27, 28, 29]

PHISHING_THRESHOLD = 0.75


def predict_url(url: str):
    # --- ML model prediction ---
    features = extract_features(url)

    # Neutralise unavailable features → scaler mean (scales to ~0)
    for idx in UNAVAILABLE_FEATURE_INDICES:
        features[0, idx] = scaler.mean_[idx]

    # Wrap in a DataFrame with the scaler's column names (if available) so that
    # sklearn does not raise a "X does not have valid feature names" UserWarning.
    if hasattr(scaler, "feature_names_in_"):
        features = pd.DataFrame(features, columns=scaler.feature_names_in_)

    features_scaled = scaler.transform(features)

    # Model classes: 0 = phishing, 1 = legitimate (UCI: -1 → 0, 1 → 1)
    ml_phishing_prob = float(model.predict_proba(features_scaled)[0][0])

    # --- Heuristic scoring ---
    heuristic = heuristic_score(url)
    h_score = heuristic["score"]

    # --- Combine: either system can flag ---
    # final = 1 - (1 - ml) * (1 - heuristic)
    combined_prob = 1 - (1 - ml_phishing_prob) * (1 - h_score)

    is_phishing = combined_prob >= PHISHING_THRESHOLD
    label = "phishing" if is_phishing else "legitimate"
    confidence = combined_prob if is_phishing else (1 - combined_prob)

    return {
        "label": label,
        "confidence": float(confidence),
        "ml_phishing_prob": round(ml_phishing_prob, 4),
        "heuristic_score": round(h_score, 4),
        "heuristic_triggers": heuristic["triggers"],
    }