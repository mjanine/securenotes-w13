import hashlib
import hmac
import secrets
import sqlite3
import traceback
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# A secret used to sign things. Keep it safe.
SECRET_KEY = "supersecret123"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- cryptographic helpers -------------------------------------------------
# BUG 2 FIX (A02:2025 – Cryptographic Failures): Added password hashing 
# instead of storing/comparing plaintext passwords.
def hash_password(password: str) -> str:
    """Hash password securely using PBKDF2 with HMAC-SHA256 and a random salt."""
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return salt.hex() + ":" + pwd_hash.hex()


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a password against its stored hash safely using constant-time comparison."""
    try:
        salt_hex, pwd_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(pwd_hash.hex(), pwd_hex)
    except Exception:
        return False


# BUG 6 FIX (A07:2025 – Identification & Authentication Failures): 
# Replaced raw incrementing user IDs as tokens with HMAC-signed tokens.
def generate_token(user_id: int) -> str:
    """Generate an HMAC-signed token containing the user ID."""
    message = str(user_id).encode("utf-8")
    signature = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"{user_id}.{signature}"


def verify_token(token: str) -> int:
    """Verify the HMAC signature of the token and return the user ID."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        user_id_str, signature = parts
        expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), user_id_str.encode("utf-8"), hashlib.sha256).hexdigest()
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
    # BUG 2 FIX: Seed users with hashed passwords instead of plaintext strings like 'admin123'
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
    """Read and verify the signed token from the Authorization header and return the user row."""
    token = (authorization or "").replace("Bearer ", "")
    
    # BUG 6 FIX (A07:2025): Verify token cryptographic signature instead of blindly trusting raw IDs
    user_id = verify_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or missing authentication token")
    
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="User not found")
    return row


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    # ORIGINAL: return JSONResponse(status_code=500, content={"error": str(exc), "trace": traceback.format_exc()})
    # CHANGE: Removed traceback.format_exc() to return a generic message.
    # WHY (A05:2025 – Security Misconfiguration): Exposing full stack traces leaks internal 
    # server paths, database details, and framework layout to attackers.
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
    # ORIGINAL: row = db.execute(f"SELECT id, password FROM users WHERE username = '{creds.username}'").fetchone()
    # CHANGE: Used parameterized query `WHERE username = ?` with tuple argument `(creds.username,)`.
    # WHY (A03:2025 – Injection): Direct string formatting allows attackers to inject malicious 
    # SQL commands (e.g., `' OR '1'='1`) to bypass authentication.
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?", (creds.username,)
    ).fetchone()
    
    if row is None or not verify_password(row["password"], creds.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # BUG 6 FIX: Return a signed token instead of the raw user ID string
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
    
    # BUG 3 FIX (A01:2025 – Broken Access Control / BOLA): 
    # Added explicit verification check so users can't read other people's notes by changing the ID.
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
    
    # ORIGINAL:
    # try:
    #     if not user["is_admin"]:
    #         raise HTTPException(status_code=403, detail="Admins only")
    # except Exception:
    #     pass  # keep going if the check has a problem
    
    # CHANGE: Removed the try...except block that was swallowing the exception.
    # WHY (A01:2025 – Broken Access Control / Broken Function Level Authorization): 
    # The original code caught the 403 error and kept execution going, allowing normal 
    # non-admin users to view all registered users.
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
        
    rows = db.execute("SELECT * FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}