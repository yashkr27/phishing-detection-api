import pandas as pd
from app.model_loader import model, scaler
from app.feature_extractor import extract_features

def predict_url(url: str):
    # Extract features
    features = extract_features(url)

    # Wrap in a DataFrame with the scaler's column names (if available) so that
    # sklearn does not raise a "X does not have valid feature names" UserWarning.
    if hasattr(scaler, "feature_names_in_"):
        features = pd.DataFrame(features, columns=scaler.feature_names_in_)

    # Scale features
    features_scaled = scaler.transform(features)

    # Predict phishing probability
    prob = model.predict_proba(features_scaled)[0][1]

    label = "phishing" if prob >= 0.5 else "legitimate"

    return {
        "label": label,
        "confidence": float(prob)
    }