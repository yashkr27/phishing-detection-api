from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel 

from app.predict import predict_url

# ----------------------------
# FastAPI app
# ----------------------------
app = FastAPI(title="Phishing Detection API")

# ----------------------------
# CORS (Development: Allow All)
#to connect FE and BE
# ----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------
# Root endpoint
# ----------------------------
@app.get("/")
def read_root():
    return {"status": "online", "message": "Phishing Detection API is running"}


# Manual OPTIONS handler removed - CORSMiddleware handles preflight correctly


# ----------------------------
# Request schema
# ----------------------------
class URLRequest(BaseModel):
    url: str



# ----------------------------
# Prediction endpoint
# ----------------------------
@app.post("/predict")
def predict(req: URLRequest):
        return predict_url(req.url)


# ----------------------------
# Debug endpoint (temp)
# ----------------------------
@app.get("/debug/scaler")
def debug_scaler():
    from app.model_loader import scaler, model
    from app.feature_extractor import extract_features
    import numpy as np
    result = {}
    if hasattr(scaler, 'feature_names_in_'):
        result["scaler_feature_names"] = list(scaler.feature_names_in_)
    result["n_features"] = int(scaler.n_features_in_)
    result["mean"] = [round(float(x), 4) for x in scaler.mean_]
    result["scale"] = [round(float(x), 4) for x in scaler.scale_]

    # Also test feature extraction for google.com
    features = extract_features("https://www.google.com")
    result["google_features"] = [float(x) for x in features[0]]
    result["google_scaled"] = [round(float(x), 4) for x in scaler.transform(features)[0]]

    return result
