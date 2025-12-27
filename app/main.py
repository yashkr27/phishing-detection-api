from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.predict import predict_url

# ----------------------------
# FastAPI app
# ----------------------------
app = FastAPI(title="Phishing Detection API")

# ----------------------------
# CORS (Frontend: localhost:5500)
# ----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
