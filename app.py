# app.py — SKYGUARD-ID Local Biometric Attendance Server (FastAPI + SQLite3 + 128-D Cosine Engine)
# Jalankan di Server Lokal (Air-Gapped LAN): uvicorn app:app --host 0.0.0.0 --port 8443

import sqlite3
import hashlib
import json
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import numpy as np

app = FastAPI(title="SKYGUARD-ID Local Biometric Server", version="4.8-LOCAL")
DB_PATH = Path(__file__).parent / "skyguard_local_biometrics.db"
ACCURACY_THRESHOLD = 98.0  # Standar wajib >= 98.0%
LIVENESS_THRESHOLD = 96.0  # Anti-spoofing 3D depth & thermal check


def init_local_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS personnel (
                emp_id TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                department TEXT NOT NULL,
                clearance_level TEXT NOT NULL,
                shift_hours TEXT NOT NULL,
                embedding_128d TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attendance_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                emp_id TEXT NOT NULL,
                full_name TEXT NOT NULL,
                gate_id TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                accuracy_pct REAL NOT NULL,
                liveness_pct REAL NOT NULL,
                status TEXT NOT NULL,
                sha256_hash TEXT NOT NULL
            )
        """)


def cosine_accuracy_percent(vec_a: list[float], vec_b: list[float]) -> float:
    a = np.array(vec_a, dtype=np.float32)
    b = np.array(vec_b, dtype=np.float32)
    sim = float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))
    return round(max(0.0, min(99.98, sim * 100.0)), 2)


class EnrollPayload(BaseModel):
    emp_id: str
    full_name: str
    department: str
    clearance_level: str
    shift_hours: str
    embedding_128d: list[float]


class ScanPayload(BaseModel):
    gate_id: str
    scan_type: str
    embedding_128d: list[float]
    liveness_score: float


@app.on_event("startup")
def startup():
    init_local_db()


@app.get("/")
def serve_ui():
    return FileResponse(Path(__file__).parent / "index.html")


@app.post("/api/v1/personnel/enroll")
def enroll_personnel(payload: EnrollPayload):
    if len(payload.embedding_128d) != 128:
        raise HTTPException(status_code=400, detail="Vektor biometrik harus 128 dimensi.")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO personnel
               (emp_id, full_name, department, clearance_level, shift_hours, embedding_128d, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                payload.emp_id,
                payload.full_name,
                payload.department,
                payload.clearance_level,
                payload.shift_hours,
                json.dumps(payload.embedding_128d),
                now_str,
            ),
        )
    return {"status": "ENROLLED", "emp_id": payload.emp_id, "created_at": now_str}


@app.post("/api/v1/gate/verify-attendance")
def verify_attendance(payload: ScanPayload):
    if payload.liveness_score < LIVENESS_THRESHOLD:
        raise HTTPException(
            status_code=403,
            detail=f"SPOOF DETECTED: Skor 3D Liveness ({payload.liveness_score}%) di bawah ambang keamanan ({LIVENESS_THRESHOLD}%).",
        )
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT emp_id, full_name, embedding_128d FROM personnel").fetchall()
        best_match = None
        best_acc = 0.0
        for emp_id, full_name, emb_json in rows:
            acc = cosine_accuracy_percent(payload.embedding_128d, json.loads(emb_json))
            if acc > best_acc:
                best_acc = acc
                best_match = (emp_id, full_name)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "VERIFIED" if best_acc >= ACCURACY_THRESHOLD else "REJECTED_LOW_CONFIDENCE"
        emp_id, full_name = best_match if best_match else ("UNKNOWN", "Subjek Tidak Dikenal")
        raw_record = f"{now_str}|{emp_id}|{payload.gate_id}|{best_acc}|{payload.liveness_score}|{status}"
        sha_hash = hashlib.sha256(raw_record.encode("utf-8")).hexdigest()

        conn.execute(
            """INSERT INTO attendance_audit_log
               (timestamp, emp_id, full_name, gate_id, scan_type, accuracy_pct, liveness_pct, status, sha256_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                now_str,
                emp_id,
                full_name,
                payload.gate_id,
                payload.scan_type,
                best_acc,
                payload.liveness_score,
                status,
                sha_hash,
            ),
        )
    return {
        "status": status,
        "emp_id": emp_id,
        "full_name": full_name,
        "accuracy_pct": best_acc,
        "liveness_pct": payload.liveness_score,
        "sha256_hash": sha_hash,
    }
