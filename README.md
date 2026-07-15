# AI Detection Rule Generator (MVP)

Generate Sigma, Google SecOps YARA-L, Splunk SPL, Microsoft Sentinel KQL, and
Elastic detection rules from a plain-English prompt, using a **100% local**
ML classifier (scikit-learn) — no OpenAI / Claude / Gemini / paid APIs.

```
Detect brute force attacks against Active Directory.
```
→ classified intent (`brute_force`, confidence %) → 5 rendered SIEM rules +
detection logic, MITRE ATT&CK mapping, severity, false positives, coverage
gaps, suggested improvements, and a rule quality score.

## How it works

```
prompt
  │
  ▼
TF-IDF + Calibrated Linear SVM  (backend/app/classifier.py)
  │  → intent label + confidence (class probability)
  ▼
intent_metadata.json  (MITRE mapping, severity, log source, FP/gap/notes per intent)
  │
  ▼
rules.py   → renders Sigma / YARA-L / Splunk / Sentinel / Elastic templates
explain.py → renders detection logic prose, "why" explanations, quality score
  │
  ▼
FastAPI (backend/app/main.py) + SQLite history
  │
  ▼
Static dashboard (frontend/index.html) — fetches http://localhost:8000
```

The classifier decides **what** the prompt is about; a template engine
decides **how** to phrase it in five different rule languages. Keeping
those two concerns separate is what makes it possible to later swap the
classifier for a local LLM (Llama/Mistral/Gemma/Phi/DeepSeek via Ollama,
say) without touching the rule-rendering or UI layers — the LLM would
just need to output the same `intent` + `params` shape.

## Run it

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

The first request trains the classifier automatically (takes well under a
second on the bundled ~140-row dataset) and saves it to
`backend/models/classifier.joblib`. Then open `frontend/index.html`
directly in a browser (no build step — it's a static file that calls
`http://localhost:8000`).

## What's implemented (MVP scope)

- Local TF-IDF + Linear SVM classifier across 14 attack-intent categories
  (~140 labeled example prompts)
- Rule generation for all 5 requested platforms: Sigma, YARA-L, Splunk SPL,
  Sentinel KQL, Elastic
- Heuristic parameter extraction from the prompt (thresholds, time windows)
  with sensible per-intent defaults when nothing is stated
- Full AI Analysis payload: detection logic, MITRE mapping, severity,
  confidence, false positives, coverage gaps, improvements, required log
  source/fields, and an explainable quality score with a breakdown
- FastAPI backend with SQLite-backed history 
- Retrain endpoint that reports train/validation accuracy, precision,
  recall, F1, and a confusion matrix
- Single-page dark "SOC dashboard" UI: prompt box, accordion rule cards
  with copy/download, AI analysis cards, dataset explorer, training
  metrics view, and generation history
