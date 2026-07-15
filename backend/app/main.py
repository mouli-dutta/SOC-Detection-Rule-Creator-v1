import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import classifier, database
from .explain import build_analysis
from .rules import generate_all_rules
from .schemas import GenerateRequest

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
METADATA_PATH = os.path.join(BASE_DIR, "data", "intent_metadata.json")

with open(METADATA_PATH) as f:
    INTENT_METADATA = json.load(f)

app = FastAPI(title="AI Detection Rule Generator", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    database.init_db()
    classifier.load_model()  # trains on first run if no saved model exists


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/generate")
def generate(req: GenerateRequest):
    prompt = req.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt must not be empty.")

    intent, confidence, proba_map = classifier.predict(prompt)
    meta = INTENT_METADATA[intent]

    rule_bundle = generate_all_rules(prompt, intent, meta)
    analysis = build_analysis(prompt, intent, meta, rule_bundle["params"], confidence)
    analysis["class_probabilities"] = proba_map

    saved = database.save_generation(prompt, intent, rule_bundle["rules"], analysis)
    return saved


@app.get("/api/history")
def history(limit: int = 50):
    return database.list_generations(limit)


@app.post("/api/history/{gen_id}/favorite")
def favorite(gen_id: int):
    ok = database.toggle_favorite(gen_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Generation not found.")
    return {"ok": True}


@app.get("/api/dataset")
def dataset():
    import pandas as pd

    df = pd.read_csv(os.path.join(BASE_DIR, "data", "training_data.csv"))
    return {
        "n_examples": len(df),
        "n_classes": df["intent"].nunique(),
        "class_counts": df["intent"].value_counts().to_dict(),
        "examples": df.to_dict(orient="records"),
    }


@app.get("/api/mitre")
def mitre():
    return {
        intent: {
            "tactic_id": m["mitre_tactic_id"],
            "tactic": m["mitre_tactic"],
            "technique_id": m["mitre_technique_id"],
            "technique": m["mitre_technique"],
            "label": m["label"],
        }
        for intent, m in INTENT_METADATA.items()
    }


@app.post("/api/train")
def retrain():
    metrics = classifier.train_model()
    return metrics


@app.get("/api/train/last")
def last_train_metrics():
    metrics = classifier.load_last_metrics()
    if metrics is None:
        raise HTTPException(status_code=404, detail="Model has not been trained yet.")
    return metrics
