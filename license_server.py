from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from typing import Optional
import sqlite3
import time
import hashlib
import os

# ==========================
# CONFIG
# ==========================

DB_PATH = "licenses.db"

LICENSE_SECRET = os.getenv("LICENSE_SECRET")
ADMIN_KEY = os.getenv("ADMIN_KEY")

if not LICENSE_SECRET or not ADMIN_KEY:
    raise RuntimeError("LICENSE_SECRET or ADMIN_KEY not set")

# ==========================
# APP
# ==========================

app = FastAPI()

# ==========================
# DATABASE
# ==========================

def db():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

with db() as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            expires INTEGER,
            hwid TEXT,
            revoked INTEGER DEFAULT 0
        )
    """)
    conn.commit()

# ==========================
# SIGNATURE
# ==========================

def sign(valid: bool, expires: int) -> str:
    msg = f"{valid}|{expires}"
    return hashlib.sha256((msg + LICENSE_SECRET).encode()).hexdigest()

# ==========================
# MODELS
# ==========================

class VerifyPayload(BaseModel):
    license: str
    hwid: str
    ts: int

class CreatePayload(BaseModel):
    license: str
    expires: int

# ==========================
# ADMIN AUTH
# ==========================

def admin_auth(key: Optional[str]):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ==========================
# ADMIN ENDPOINTS
# ==========================

@app.post("/admin/create")
def create_license(
    payload: CreatePayload,
    x_admin_key: Optional[str] = Header(None)
):
    admin_auth(x_admin_key)

    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO licenses (key, expires, hwid, revoked) VALUES (?, ?, NULL, 0)",
            (payload.license, payload.expires)
        )
        conn.commit()

    return {"status": "created", "license": payload.license}


@app.post("/admin/revoke")
def revoke_license(
    license: str,
    x_admin_key: Optional[str] = Header(None)
):
    admin_auth(x_admin_key)

    with db() as conn:
        conn.execute(
            "UPDATE licenses SET revoked = 1 WHERE key = ?",
            (license,)
        )
        conn.commit()

    return {"status": "revoked", "license": license}


@app.get("/admin/licenses")
def list_licenses(
    x_admin_key: Optional[str] = Header(None)
):
    admin_auth(x_admin_key)

    with db() as conn:
        rows = conn.execute(
            "SELECT key, expires, hwid, revoked FROM licenses"
        ).fetchall()

    return [
        {
            "license": r[0],
            "expires": r[1],
            "hwid": r[2],
            "revoked": bool(r[3])
        }
        for r in rows
    ]

# ==========================
# VERIFY ENDPOINT
# ==========================

@app.post("/api/license/verify")
def verify_license(payload: VerifyPayload):
    now = int(time.time())

    with db() as conn:
        row = conn.execute(
            "SELECT expires, hwid, revoked FROM licenses WHERE key = ?",
            (payload.license,)
        ).fetchone()

    # License not found
    if not row:
        return {
            "valid": False,
            "expires": 0,
            "signature": sign(False, 0)
        }

    expires, hwid, revoked = row

    # Revoked
    if revoked:
        return {
            "valid": False,
            "expires": expires,
            "signature": sign(False, expires)
        }

    # Expired
    if expires < now:
        return {
            "valid": False,
            "expires": expires,
            "signature": sign(False, expires)
        }

    # First HWID bind
    if hwid is None:
        with db() as conn:
            conn.execute(
                "UPDATE licenses SET hwid = ? WHERE key = ?",
                (payload.hwid, payload.license)
            )
            conn.commit()

    # HWID mismatch
    elif hwid != payload.hwid:
        return {
            "valid": False,
            "expires": expires,
            "signature": sign(False, expires)
        }

    # ✅ VALID
    return {
        "valid": True,
        "expires": expires,
        "signature": sign(True, expires)
    }
