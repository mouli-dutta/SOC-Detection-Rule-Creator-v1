import json
import os
import sqlite3
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "app.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS generations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            intent TEXT NOT NULL,
            rules_json TEXT NOT NULL,
            analysis_json TEXT NOT NULL,
            favorite INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_generation(prompt: str, intent: str, rules: dict, analysis: dict) -> dict:
    conn = get_conn()
    created_at = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO generations (prompt, intent, rules_json, analysis_json, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (prompt, intent, json.dumps(rules), json.dumps(analysis), created_at),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return {
        "id": row_id,
        "prompt": prompt,
        "rules": rules,
        "analysis": analysis,
        "created_at": created_at,
    }


def list_generations(limit: int = 50) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, prompt, intent, rules_json, analysis_json, favorite, created_at "
        "FROM generations ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "prompt": r["prompt"],
            "intent": r["intent"],
            "rules": json.loads(r["rules_json"]),
            "analysis": json.loads(r["analysis_json"]),
            "favorite": bool(r["favorite"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def toggle_favorite(gen_id: int) -> bool:
    conn = get_conn()
    row = conn.execute("SELECT favorite FROM generations WHERE id = ?", (gen_id,)).fetchone()
    if row is None:
        conn.close()
        return False
    new_val = 0 if row["favorite"] else 1
    conn.execute("UPDATE generations SET favorite = ? WHERE id = ?", (new_val, gen_id))
    conn.commit()
    conn.close()
    return True
