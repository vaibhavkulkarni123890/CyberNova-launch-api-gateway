#!/usr/bin/env python3
"""
Simplified backend for testing
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import json, random, jwt, sqlite3, bcrypt
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any

# Configuration
JWT_SECRET = "cybernova-ai-secret-key-2025"
JWT_ALGORITHM = "HS256"
DATABASE_PATH = "cybernova.db"

# Security
security = HTTPBearer()

# Create FastAPI app
app = FastAPI(title="CyberNova AI - Simplified Backend", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic Models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    company: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# Database Functions
def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            company TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Utility Functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: int, email: str) -> str:
    """Create JWT token"""
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    payload = verify_jwt_token(credentials.credentials)
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ? AND is_active = TRUE", 
        (payload["user_id"],)
    ).fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return dict(user)

# Initialize database on startup
init_database()

# Routes
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "CyberNova AI Backend",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/auth/register")
async def register_user(user_data: UserRegister):
    """Register new user"""
    conn = get_db_connection()
    
    # Check if user already exists
    existing_user = conn.execute(
        "SELECT id FROM users WHERE email = ?", (user_data.email,)
    ).fetchone()
    
    if existing_user:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password and create user
    password_hash = hash_password(user_data.password)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, full_name, company) VALUES (?, ?, ?, ?)",
        (user_data.email, password_hash, user_data.full_name, user_data.company)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Create JWT token
    token = create_jwt_token(user_id, user_data.email)
    
    return {
        "message": "User registered successfully",
        "token": token,
        "user": {
            "id": user_id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "company": user_data.company
        }
    }

@app.post("/api/auth/login")
async def login_user(login_data: UserLogin):
    """Login user"""
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ? AND is_active = TRUE", 
        (login_data.email,)
    ).fetchone()
    conn.close()
    
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_jwt_token(user["id"], user["email"])
    
    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "company": user["company"]
        }
    }

@app.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "company": current_user["company"],
        "created_at": current_user["created_at"]
    }

@app.get("/api/dashboard/stats")
async def dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get dashboard statistics"""
    return {
        "totalThreats": random.randint(0, 10),
        "activeAlerts": random.randint(0, 5),
        "riskScore": random.randint(0, 100),
        "systemHealth": random.randint(80, 100),
        "lastScanTime": datetime.utcnow().isoformat(),
        "scanStatus": "completed"
    }

@app.get("/api/dashboard/alerts")
async def dashboard_alerts(current_user: dict = Depends(get_current_user)):
    """Get dashboard alerts"""
    return []

@app.get("/api/scan/latest")
async def get_latest_scan(current_user: dict = Depends(get_current_user)):
    """Get latest scan results"""
    return {
        "scan_info": {"id": "test_scan", "created_at": datetime.utcnow().isoformat()},
        "system_info": {"hostname": "test-computer", "platform": "Windows"},
        "network_connections": [],
        "suspicious_processes": [],
        "risky_ports": [],
        "recommendations": []
    }

@app.post("/api/system/scan")
@app.post("/api/scan/start")
async def start_system_scan(current_user: dict = Depends(get_current_user)):
    """Start a system scan"""
    return {
        "message": "System scan completed successfully",
        "scan_id": f"scan_{int(datetime.utcnow().timestamp())}",
        "threats_detected": random.randint(0, 3),
        "recommendations_count": random.randint(0, 5)
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Simplified CyberNova AI Backend...")
    uvicorn.run(app, host="0.0.0.0", port=8080)