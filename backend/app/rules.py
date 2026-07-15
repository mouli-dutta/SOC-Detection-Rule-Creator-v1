"""
Rule template engine.

Given a classified intent + a few parameters extracted from the natural
language prompt (threshold, time window, free-text description), renders
concrete detection rules for five SIEM/EDR rule languages.

This module is intentionally template-driven (not another ML model) --
the ML classifier's job is to pick the *intent*; this module's job is to
turn that intent into syntactically valid rule text. This keeps the two
concerns separable, which is also what makes it easy to swap the
classifier for a local LLM later (see AI_ARCHITECTURE.md).
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any


LOGSOURCE_MAP = {
    "brute_force": {"category": "authentication", "product": "windows"},
    "credential_access": {"category": "process_access", "product": "windows"},
    "malware": {"category": "process_creation", "product": "windows"},
    "powershell": {"category": "ps_script", "product": "windows"},
    "lateral_movement": {"category": "network_connection", "product": "windows"},
    "persistence": {"category": "process_creation", "product": "windows"},
    "ransomware": {"category": "file_event", "product": "windows"},
    "phishing": {"category": "email", "product": "m365"},
    "privilege_escalation": {"category": "audit", "product": "windows"},
    "data_exfiltration": {"category": "network_connection", "product": "any"},
    "web_attacks": {"category": "web", "product": "web_server"},
    "cloud_attacks": {"category": "cloud_audit", "product": "cloud"},
    "living_off_the_land": {"category": "process_creation", "product": "windows"},
    "reconnaissance": {"category": "network_connection", "product": "any"},
}


def extract_params(prompt: str, meta: dict) -> dict:
    """Very small heuristic extractor: look for numbers + time units in the
    prompt to override the intent's default threshold / window. Falls back
    to the metadata defaults when nothing is found."""
    threshold = meta["default_threshold"]
    window = meta["default_window_minutes"]

    num_match = re.search(r"(more than|over|greater than|>)\s*(\d+)", prompt, re.I)
    if num_match:
        threshold = int(num_match.group(2))
    else:
        bare_num = re.search(r"\b(\d+)\b", prompt)
        if bare_num:
            threshold = int(bare_num.group(1))

    window_match = re.search(r"(\d+)\s*(minute|min|hour|hr|second|sec)s?", prompt, re.I)
    if window_match:
        val = int(window_match.group(1))
        unit = window_match.group(2).lower()
        if "hour" in unit or unit == "hr":
            val *= 60
        elif "sec" in unit:
            val = max(1, val // 60)
        window = val

    return {"threshold": threshold, "window_minutes": window}


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def title_case(intent_label: str, prompt: str) -> str:
    return f"{intent_label} - {prompt.strip().rstrip('.').capitalize()}"


def gen_sigma(prompt: str, intent: str, meta: dict, params: dict) -> str:
    ls = LOGSOURCE_MAP.get(intent, {"category": "process_creation", "product": "windows"})
    rule_id = str(uuid.uuid4())
    title = title_case(meta["label"], prompt)
    return f"""title: {title}
id: {rule_id}
status: experimental
description: {meta['label']} detection generated from prompt: "{prompt.strip()}"
references:
    - https://attack.mitre.org/techniques/{meta['mitre_technique_id']}/
author: AI Detection Rule Generator
date: {datetime.utcnow().strftime('%Y/%m/%d')}
tags:
    - attack.{slugify(meta['mitre_tactic'])}
    - attack.{meta['mitre_technique_id'].lower()}
logsource:
    category: {ls['category']}
    product: {ls['product']}
detection:
    selection:
        EventID: 4625
    timeframe: {params['window_minutes']}m
    condition: selection | count() by SourceIP > {params['threshold']}
falsepositives:
{chr(10).join('    - ' + fp for fp in meta['false_positives'])}
level: {meta['default_severity'].lower()}
"""


def gen_yara_l(prompt: str, intent: str, meta: dict, params: dict) -> str:
    rule_name = "Detect" + "".join(w.capitalize() for w in slugify(meta["label"]).split("_"))
    return f"""rule {rule_name} {{

  meta:
    author = "AI Detection Rule Generator"
    description = "{meta['label']} detection generated from prompt: {prompt.strip()}"
    mitre_tactic = "{meta['mitre_tactic_id']} {meta['mitre_tactic']}"
    mitre_technique = "{meta['mitre_technique_id']} {meta['mitre_technique']}"
    severity = "{meta['default_severity']}"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK" or $e.security_result.action = "FAIL"

  match:
    $e.principal.hostname over {params['window_minutes']}m

  condition:
    #e > {params['threshold']}
}}
"""


def gen_splunk(prompt: str, intent: str, meta: dict, params: dict) -> str:
    return f"""`comment("{meta['label']} detection generated from prompt: {prompt.strip()}")`
index=* sourcetype=WinEventLog:Security OR sourcetype=auth
| bucket _time span={params['window_minutes']}m
| stats count by _time, src_ip, user
| where count > {params['threshold']}
| eval mitre_technique="{meta['mitre_technique_id']}", severity="{meta['default_severity']}"
| sort - count
"""


def gen_sentinel(prompt: str, intent: str, meta: dict, params: dict) -> str:
    return f"""// {meta['label']} detection generated from prompt: {prompt.strip()}
// MITRE ATT&CK: {meta['mitre_technique_id']} - {meta['mitre_technique']}
SigninLogs
| where TimeGenerated > ago({max(1, params['window_minutes'] // 60) if params['window_minutes'] >= 60 else 1}h)
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, {params['window_minutes']}m)
| where FailedAttempts > {params['threshold']}
| project TimeGenerated, IPAddress, UserPrincipalName, FailedAttempts
| extend Severity = "{meta['default_severity']}"
"""


def gen_elastic(prompt: str, intent: str, meta: dict, params: dict) -> str:
    ls = LOGSOURCE_MAP.get(intent, {"category": "process_creation", "product": "windows"})
    return f"""{{
  "query": {{
    "bool": {{
      "filter": [
        {{ "term": {{ "event.category": "{ls['category']}" }} }},
        {{ "term": {{ "event.outcome": "failure" }} }}
      ]
    }}
  }},
  "aggs": {{
    "by_source": {{
      "terms": {{ "field": "source.ip" }},
      "aggs": {{
        "over_threshold": {{
          "bucket_selector": {{
            "buckets_path": {{ "count": "_count" }},
            "script": "params.count > {params['threshold']}"
          }}
        }}
      }}
    }}
  }},
  "_meta": {{
    "description": "{meta['label']} detection generated from prompt: {prompt.strip()}",
    "mitre_technique": "{meta['mitre_technique_id']}",
    "window_minutes": {params['window_minutes']}
  }}
}}
"""


GENERATORS = {
    "sigma": gen_sigma,
    "yara_l": gen_yara_l,
    "splunk": gen_splunk,
    "sentinel": gen_sentinel,
    "elastic": gen_elastic,
}


def generate_all_rules(prompt: str, intent: str, meta: dict) -> dict[str, Any]:
    params = extract_params(prompt, meta)
    rules = {name: fn(prompt, intent, meta, params) for name, fn in GENERATORS.items()}
    return {"rules": rules, "params": params}
