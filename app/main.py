from fastapi import FastAPI
from pydantic import BaseModel
from app.predict import predict_url

app = FastAPI(title="Phishing Detection API")

class URLRequest(BaseModel):
    url: str

@app.post("/predict")
def predict(req: URLRequest):
    return predict_url(req.url)
