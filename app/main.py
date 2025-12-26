from fastapi import FastAPI
from app.schemas import URLRequest
from app.predict import predict_url

app = FastAPI(
    title="Phishing Detection API",
    version="1.0.0"
)

@app.post("/predict")
def predict(request: URLRequest):
    return predict_url(request.url)
