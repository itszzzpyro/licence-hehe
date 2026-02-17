from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from typing import Optional
import psycopg2
import time
import hashlib
import os

# ==========================
# CONFIG
# ==========================

DATABASE_URL = os.getenv("DATABASE_URL")
LICENSE_SECRET = os.getenv("LICENSE_SECRET")
ADMIN_KEY = os.getenv("ADMIN_KEY")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

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
    return psycopg2.connect(DATABASE_URL)

# Create table on startup
with db() as conn:
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY,
                expires BIGINT,
                hwid TEXT,
                revoked BOOLEAN DEFAULT FALSE
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
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO licenses (key, expires, hwid, revoked)
                VALUES (%s, %s, NULL, FALSE)
                ON CONFLICT (key)
                DO UPDATE SET
                    expires = EXCLUDED.expires,
                    revoked = FALSE
            """, (payload.license, payload.expires))
            conn.commit()

    return {"status": "created", "license": payload.license}


@app.post("/admin/revoke")
def revoke_license(
    license: str,
    x_admin_key: Optional[str] = Header(None)
):
    admin_auth(x_admin_key)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE licenses SET revoked = TRUE WHERE key = %s",
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
        with conn.cursor() as cur:
            cur.execute(
                "SELECT key, expires, hwid, revoked FROM licenses"
            )
            rows = cur.fetchall()

    return [
        {
            "license": r[0],
            "expires": r[1],
            "hwid": r[2],
            "revoked": r[3]
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
        with conn.cursor() as cur:
            cur.execute(
                "SELECT expires, hwid, revoked FROM licenses WHERE key = %s",
                (payload.license,)
            )
            row = cur.fetchone()

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
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE licenses SET hwid = %s WHERE key = %s",
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

    # VALID
    return {
        "valid": True,
        "expires": expires,
        "signature": sign(True, expires)
    }
