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
    CORSMiddleware, #cross origin resource sharing 
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


# Manually handle OPTIONS for CORS troubleshooting if needed
@app.options("/{path:path}")
def options_handler(path: str):
    return {"status": "ok"}


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

