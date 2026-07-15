"""
Builds the "AI Analysis" payload: detection logic explanation, MITRE
mapping, severity, confidence, false positives, coverage gaps,
improvements, and a rule quality score with a "why" breakdown for each
generated field.
"""
from __future__ import annotations


def detection_logic_text(meta: dict, params: dict) -> str:
    return (
        f"This rule flags {meta['label'].lower()} activity when more than "
        f"{params['threshold']} matching events occur from the same entity "
        f"within a {params['window_minutes']}-minute window, based on "
        f"{meta['log_source']}."
    )


def why_threshold(meta: dict, params: dict) -> str:
    return (
        f"Threshold = {params['threshold']}. Chosen because {meta['label'].lower()} "
        f"activity of this kind typically produces multiple related events in a "
        f"short period; a default of {meta['default_threshold']} balances "
        f"catching real activity against noisy single-event false positives."
    )


def why_window(meta: dict, params: dict) -> str:
    return (
        f"Time window = {params['window_minutes']} minutes. This groups related "
        f"events together without spanning long enough to merge unrelated, "
        f"coincidental activity from the same source."
    )


def why_severity(meta: dict) -> str:
    return (
        f"Severity = {meta['default_severity']}. Based on the MITRE tactic "
        f"({meta['mitre_tactic']}) this technique maps to and its typical "
        f"potential impact if successful and undetected."
    )


def quality_score(confidence: float, meta: dict, params: dict) -> dict:
    # Simple, explainable heuristic scoring across 5 sub-dimensions (0-100 each).
    accuracy = round(60 + confidence * 35)  # classifier confidence drives this
    coverage = 70 if len(meta["coverage_gaps"]) <= 3 else 60
    noise = max(40, 90 - len(meta["false_positives"]) * 8)
    performance = 90  # templated rules are cheap to evaluate
    portability = 85  # rule renders across all 5 platforms by construction

    overall = round((accuracy + coverage + noise + performance + portability) / 5)
    return {
        "overall": overall,
        "breakdown": {
            "accuracy": accuracy,
            "coverage": coverage,
            "noise": noise,
            "performance": performance,
            "portability": portability,
        },
        "explanation": (
            f"Accuracy reflects classifier confidence ({round(confidence * 100)}%). "
            f"Coverage and noise are derived from the number of known blind spots "
            f"({len(meta['coverage_gaps'])}) and expected false-positive sources "
            f"({len(meta['false_positives'])}) for this technique. Performance and "
            f"portability are high because the rule uses simple threshold logic "
            f"available in all five target platforms."
        ),
    }


def build_analysis(prompt: str, intent: str, meta: dict, params: dict, confidence: float) -> dict:
    return {
        "intent": intent,
        "intent_label": meta["label"],
        "detection_logic": detection_logic_text(meta, params),
        "mitre": {
            "tactic_id": meta["mitre_tactic_id"],
            "tactic": meta["mitre_tactic"],
            "technique_id": meta["mitre_technique_id"],
            "technique": meta["mitre_technique"],
        },
        "severity": meta["default_severity"],
        "confidence": round(confidence * 100, 1),
        "false_positives": meta["false_positives"],
        "coverage_gaps": meta["coverage_gaps"],
        "improvements": meta["improvements"],
        "required_log_source": meta["log_source"],
        "required_fields": meta["required_fields"],
        "threshold": params["threshold"],
        "window_minutes": params["window_minutes"],
        "quality_score": quality_score(confidence, meta, params),
        "why": {
            "threshold": why_threshold(meta, params),
            "window": why_window(meta, params),
            "severity": why_severity(meta),
        },
    }
