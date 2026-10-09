import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import traceback
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# FEEDBACK FIX: Move SECRET_KEY to an environment variable with a safe fallback
SECRET_KEY = os.environ.get("SECRET_KEY", "supersecret123")

# FEEDBACK FIX: Restrict CORS to trusted origins instead of wildcard ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- cryptographic helpers -------------------------------------------------
def hash_password(password: str) -> str:
    """Hash password securely using PBKDF2 with HMAC-SHA256, a random salt, and 600,000 iterations."""
    salt = secrets.token_bytes(16)
    # FEEDBACK FIX: Increased iteration count from 100,000 to 600,000 for stronger protection
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600000)
    return salt.hex() + ":" + pwd_hash.hex()


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a password against its stored hash safely using constant-time comparison."""
    try:
        salt_hex, pwd_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        # FEEDBACK FIX: Updated to 600,000 iterations to match hashing function
        pwd_hash = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt, 600000)
        return hmac.compare_digest(pwd_hash.hex(), pwd_hex)
    except Exception:
        return False


def generate_token(user_id: int) -> str:
    """Generate an HMAC-signed token with an expiration timestamp (1 hour)."""
    # FEEDBACK FIX: Add expiration timestamp (current time + 3600 seconds / 1 hour)
    expiry = int(time.time()) + 3600
    message = f"{user_id}.{expiry}".encode("utf-8")
    signature = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"{user_id}.{expiry}.{signature}"


def verify_token(token: str) -> int:
    """Verify the HMAC signature and check token expiration, then return user ID."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        user_id_str, expiry_str, signature = parts
        
        # FEEDBACK FIX: Check if token has expired
        if int(time.time()) > int(expiry_str):
            return None
            
        message = f"{user_id_str}.{expiry_str}".encode("utf-8")
        expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()
        
        if hmac.compare_digest(signature, expected_sig):
            return int(user_id_str)
    except Exception:
        pass
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
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", ("admin", hash_password("admin123")))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", ("alice", hash_password("alicepass")))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", ("bob", hash_password("bobpass")))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3,'Bob plans','Bob secret note')")
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
def current_user(authorization: str = Header(default=None)):
    token = (authorization or "").replace("Bearer ", "")
    user_id = verify_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired authentication token")
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="User not found")
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
    hashed_pwd = hash_password(creds.password)
    try:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (creds.username, hashed_pwd),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already registered")
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?", (creds.username,)
    ).fetchone()
    if row is None or not verify_password(row["password"], creds.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"token": generate_token(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    if row["owner_id"] != user["id"] and not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Access denied to this note")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    
    # FEEDBACK FIX: Select only safe columns instead of all columns (to avoid exposing password hashes)
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}