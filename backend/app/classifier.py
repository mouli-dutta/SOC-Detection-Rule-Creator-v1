"""
Local, offline ML classifier: TF-IDF vectorizer + Linear SVM, wrapped in
CalibratedClassifierCV so we get class probabilities (used as the
"confidence" score) rather than just raw margins. No network calls,
no external AI APIs -- trains in well under a second on this dataset.
"""
from __future__ import annotations

import json
import os

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "training_data.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "classifier.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "models", "last_train_metrics.json")


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("clf", CalibratedClassifierCV(LinearSVC(C=1.0, class_weight="balanced"), cv=3)),
        ]
    )


def train_model() -> dict:
    df = pd.read_csv(DATA_PATH)
    X, y = df["prompt"], df["intent"]

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    train_pred = pipeline.predict(X_train)
    val_pred = pipeline.predict(X_val)

    labels = sorted(y.unique())
    cm = confusion_matrix(y_val, val_pred, labels=labels).tolist()

    metrics = {
        "train_accuracy": round(accuracy_score(y_train, train_pred), 4),
        "validation_accuracy": round(accuracy_score(y_val, val_pred), 4),
        "precision": round(precision_score(y_val, val_pred, average="macro", zero_division=0), 4),
        "recall": round(recall_score(y_val, val_pred, average="macro", zero_division=0), 4),
        "f1_score": round(f1_score(y_val, val_pred, average="macro", zero_division=0), 4),
        "labels": labels,
        "confusion_matrix": cm,
        "n_train": len(X_train),
        "n_val": len(X_val),
        "n_classes": len(labels),
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    # Refit on ALL data for the deployed model, keep held-out metrics for reporting.
    final_pipeline = build_pipeline()
    final_pipeline.fit(X, y)
    joblib.dump(final_pipeline, MODEL_PATH)

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    return metrics


def load_model():
    if not os.path.exists(MODEL_PATH):
        train_model()
    return joblib.load(MODEL_PATH)


def load_last_metrics() -> dict | None:
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH) as f:
            return json.load(f)
    return None


def predict(prompt: str) -> tuple[str, float, dict]:
    model = load_model()
    intent = model.predict([prompt])[0]
    proba = model.predict_proba([prompt])[0]
    classes = model.classes_
    confidence = float(max(proba))
    proba_map = {cls: round(float(p), 4) for cls, p in zip(classes, proba)}
    return intent, confidence, proba_map


if __name__ == "__main__":
    m = train_model()
    print(json.dumps(m, indent=2))
