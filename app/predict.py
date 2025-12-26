import numpy as np
from app.model_loader import model, scaler
from app.feature_extractor import extract_features

def predict_url(url: str):
    features = extract_features(url)
    scaled = scaler.transform(features)

    proba = model.predict_proba(scaled)[0]
    phishing_prob = float(proba[1])

    label = "phishing" if phishing_prob >= 0.5 else "legitimate"

    return {
        "label": label,
        "confidence": phishing_prob
    }
