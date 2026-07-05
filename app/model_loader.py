import joblib
import os

# Resolve paths relative to this file so the server can be started
# from any working directory without duplicating model files.
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH  = os.path.join(_BASE_DIR, "models", "xgboost_phishing_model.joblib")
SCALER_PATH = os.path.join(_BASE_DIR, "models", "phishing_scaler.joblib")

model  = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
