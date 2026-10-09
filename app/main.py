"""
SecureNotes API  —  Week 13 Security Lab (STUDENT VERSION)
Web Systems and Technologies
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable must be set for security.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# --- cryptographic helpers -------------------------------------------------
def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000,
    )
    return f"{salt.hex()}:{pwd_hash.hex()}"


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a password hash using constant-time comparison."""
    try:
        salt_hex, pwd_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            provided_password.encode("utf-8"),
            salt,
            600_000,
        )
        return hmac.compare_digest(pwd_hash.hex(), pwd_hex)
    except (ValueError, TypeError, AttributeError):
        return False


def generate_token(user_id: int) -> str:
    """Generate an HMAC-signed token that expires after one hour."""
    expiry = int(time.time()) + 3600
    message = f"{user_id}.{expiry}"
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{user_id}.{expiry}.{signature}"


def verify_token(token: str):
    """Verify the token structure, signature, and expiration."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        user_id_str, expiry_str, signature = parts
        user_id = int(user_id_str)
        expiry = int(expiry_str)

        if user_id <= 0 or expiry <= int(time.time()):
            return None
        if len(signature) != 64:
            return None

        message = f"{user_id_str}.{expiry_str}"
        expected_signature = hmac.new(
            SECRET_KEY.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return None

        return user_id
    except (ValueError, TypeError, AttributeError):
        return None


# --- database (SQLite, created fresh on startup) ---------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ("admin", hash_password("admin123"), 1))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ("alice", hash_password("alicepass"), 0))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ("bob", hash_password("bobpass"), 0))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", (2, "Alice diary", "Alice secret note"))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", (3, "Bob plans", "Bob secret note"))
    db.commit()


init_db()


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- auth helper -----------------------------------------------------------
def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Read the token from the HTTPBearer dependency and return the user row."""
    token = credentials.credentials.strip()
    user_id = verify_token(token)
    
    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token",
        )

    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(
            status_code=401,
            detail="User not found",
        )
    return row


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    username = creds.username.strip()
    if not username or not creds.password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    
    hashed_pwd = hash_password(creds.password)
    try:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (username, hashed_pwd),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    return {"message": f"user {username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()
    
    if row is None or not verify_password(row["password"], creds.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    return {"token": generate_token(row["id"])}


@app.get("/notes")
def list_my_notes(user=Depends(current_user)):
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user)):
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
        
    if row["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied to this note")
        
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, user=Depends(current_user)):
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(user=Depends(current_user)):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
        
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}