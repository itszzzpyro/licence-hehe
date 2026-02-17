from fastapi import FastAPI
from pydantic import BaseModel
import hashlib
import time
import os

app = FastAPI()

SECRET = os.getenv("LICENSE_SECRET")
if not SECRET:
    raise RuntimeError("LICENSE_SECRET not set")

LICENSES = {
    "ABC-123-XYZ": {
        "hwid": None,
        "expires": 1760000000,
        "revoked": False
    }
}

class LicenseRequest(BaseModel):
    license: str
    hwid: str
    ts: int

@app.post("/api/license/verify")
def verify_license(payload: LicenseRequest):
    lic = LICENSES.get(payload.license)

    if not lic or lic["revoked"] or lic["expires"] < time.time():
        return {"valid": False}

    if lic["hwid"] is None:
        lic["hwid"] = payload.hwid
    elif lic["hwid"] != payload.hwid:
        return {"valid": False}

    msg = f"True|{lic['expires']}"
    signature = hashlib.sha256((msg + SECRET).encode()).hexdigest()

    return {
        "valid": True,
        "expires": lic["expires"],
        "signature": signature
    }