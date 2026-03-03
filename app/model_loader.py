import joblib

#to load model files
MODEL_PATH = "models/xgboost_phishing_model.joblib"
SCALER_PATH = "models/phishing_scaler.joblib"

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
