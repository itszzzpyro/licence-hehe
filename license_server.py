from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
import hashlib
import time
import os
import sqlite3
from typing import Optional

# ================== CONFIG ==================
DB_PATH = "licenses.db"
SECRET = os.getenv("LICENSE_SECRET")
ADMIN_KEY = os.getenv("ADMIN_KEY")

if not SECRET:
    raise RuntimeError("LICENSE_SECRET not set")
if not ADMIN_KEY:
    raise RuntimeError("ADMIN_KEY not set")

app = FastAPI()

# ================== DATABASE ==================
def db():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            license TEXT PRIMARY KEY,
            hwid TEXT,
            expires INTEGER,
            revoked INTEGER DEFAULT 0
        )
        """)
init_db()

# ================== MODELS ==================
class LicenseRequest(BaseModel):
    license: str
    hwid: str
    ts: int

class AdminCreate(BaseModel):
    license: str
    expires: int

# ================== RATE LIMIT ==================
RATE_LIMIT = {}  # ip -> [count, reset_time]

def check_rate_limit(ip: str):
    now = time.time()
    entry = RATE_LIMIT.get(ip)

    if not entry or now > entry[1]:
        RATE_LIMIT[ip] = [1, now + 60]
        return

    if entry[0] >= 30:
        raise HTTPException(429, "Too many requests")

    entry[0] += 1

# ================== VERIFY ENDPOINT ==================
@app.post("/api/license/verify")
def verify_license(
    payload: LicenseRequest,
    request: Request
):
    ip = request.client.host
    check_rate_limit(ip)

    with db() as conn:
        cur = conn.execute(
            "SELECT hwid, expires, revoked FROM licenses WHERE license=?",
            (payload.license,)
        )
        row = cur.fetchone()

    if not row:
        return {"valid": False}

    hwid, expires, revoked = row

    if revoked or expires < time.time():
        return {"valid": False}

    # Bind HWID
    if hwid is None:
        with db() as conn:
            conn.execute(
                "UPDATE licenses SET hwid=? WHERE license=?",
                (payload.hwid, payload.license)
            )
    elif hwid != payload.hwid:
        return {"valid": False}

    msg = f"True|{expires}"
    signature = hashlib.sha256((msg + SECRET).encode()).hexdigest()

    return {
        "valid": True,
        "expires": expires,
        "signature": signature
    }

# ================== ADMIN AUTH ==================
def admin_auth(key: Optional[str]):
    if key != ADMIN_KEY:
        raise HTTPException(401, "Unauthorized")

# ================== ADMIN ENDPOINTS ==================
@app.post("/admin/create")
def admin_create(
    payload: AdminCreate,
    x_admin_key: Optional[str] = Header(None)
):
    admin_auth(x_admin_key)

    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO licenses (license, hwid, expires, revoked) VALUES (?, NULL, ?, 0)",
            (payload.license, payload.expires)
        )

    return {"status": "created"}

@app.post("/admin/revoke/{license_key}")
def admin_revoke(
    license_key: str,
    x_admin_key: Optional[str] = Header(None)
):
    admin_auth(x_admin_key)

    with db() as conn:
        conn.execute(
            "UPDATE licenses SET revoked=1 WHERE license=?",
            (license_key,)
        )

    return {"status": "revoked"}

@app.post("/admin/reset/{license_key}")
def admin_reset_hwid(
    license_key: str,
    x_admin_key: Optional[str] = Header(None)
):
    admin_auth(x_admin_key)

    with db() as conn:
        conn.execute(
            "UPDATE licenses SET hwid=NULL WHERE license=?",
            (license_key,)
        )

    return {"status": "hwid reset"}
