import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "xgboost_phishing_model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "models", "phishing_scaler.joblib")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
