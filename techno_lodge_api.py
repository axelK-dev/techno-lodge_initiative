import os
import sqlite3
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import jwt

SECRET_KEY = "techno_lodge_secret"
ROLES = ["Explorer", "Builder", "Mentor", "Innovator"]
ALGORITHM = "HS256"

DB_FILE = "techno_lodge_devices.db"
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT UNIQUE, status TEXT, trust_chain BOOLEAN)")
conn.commit()

app = FastAPI(title="Techno-Lodge API", version="1.0")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_token(username: str, role: str):
    payload = {"sub": username, "role": role}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    return verify_token(token)

class LoginRequest(BaseModel):
    username: str
    role: str

class OnboardingRequest(BaseModel):
    device_id: str
    user_age: int

class ComplianceRequest(BaseModel):
    workflow: Dict[str, Any]

@app.post("/login")
async def login(request: LoginRequest):
    if request.role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    token = create_token(request.username, request.role)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/onboard")
async def onboard_device(request: OnboardingRequest, user: dict = Depends(get_current_user)):
    if request.user_age < 13:
        return {"message": "Parental consent required for minors"}
    try:
        cursor.execute("INSERT INTO devices (device_id, status, trust_chain) VALUES (?, ?, ?)", (request.device_id, "Provisioned", True))
        conn.commit()
        return {"message": "Device onboarded successfully", "device_id": request.device_id}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Device already exists")

@app.post("/compliance")
async def validate_compliance(request: ComplianceRequest, user: dict = Depends(get_current_user)):
    compliance_rules = {"HIPAA": True, "COPPA": True, "FERPA": True, "CIPA": True}
    for rule, expected in compliance_rules.items():
        if request.workflow.get(rule) != expected:
            return {"compliance_passed": False, "failed_rule": rule}
    return {"compliance_passed": True}

@app.get("/health")
async def health_check():
    return {"status": "API running", "version": "1.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("techno_lodge_api:app", host="127.0.0.1", port=8000, reload=True)
