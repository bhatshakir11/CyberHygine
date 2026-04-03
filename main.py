from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import psycopg2
import os
import bcrypt
import jwt
from datetime import datetime, timedelta

# ================== APP ==================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "CyberHygine Backend Running 🚀"}

@app.head("/")
def head_home():
    return {}

# ================== DB ==================
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

# ================== AUTH ==================
JWT_SECRET = os.getenv("JWT_SECRET", "secret")
ALGORITHM = "HS256"
auth_scheme = HTTPBearer()

def create_token(user_id):
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(minutes=60)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# ================== MODELS ==================
class User(BaseModel):
    username: str
    password: str

class Credential(BaseModel):
    site: str
    username: str
    password: str
    strength: str

class Note(BaseModel):
    title: str
    content: str

# ================== INIT TABLES ==================
def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        site TEXT,
        username TEXT,
        password TEXT,
        strength TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        title TEXT,
        content TEXT
    )
    """)

    conn.commit()
    cur.close()
    conn.close()

init_db()

# ================== AUTH ROUTES ==================
@app.post("/api/register")
def register(user: User):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username=%s", (user.username,))
    if cur.fetchone():
        return {"success": False, "message": "Username already exists"}

    hashed = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())

    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
        (user.username, hashed)
    )

    conn.commit()
    conn.close()

    return {"success": True, "message": "User registered"}

@app.post("/api/login")
def login(user: User):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, password_hash FROM users WHERE username=%s", (user.username,))
    row = cur.fetchone()

    conn.close()

    if not row:
        return {"success": False}

    if bcrypt.checkpw(user.password.encode(), row[1].encode()):
        return {"success": True, "token": create_token(row[0])}

    return {"success": False}

# ================== CREDENTIALS ==================
@app.post("/api/credentials")
def add_credential(data: Credential, user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO credentials (user_id, site, username, password, strength)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
    """, (user_id, data.site, data.username, data.password, data.strength))

    cred_id = cur.fetchone()[0]
    conn.commit()
    conn.close()

    return {"id": cred_id}

@app.get("/api/credentials")
def get_credentials(user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, site, username, password, strength FROM credentials WHERE user_id=%s", (user_id,))
    rows = cur.fetchall()

    conn.close()

    return [
        {"id": r[0], "site": r[1], "username": r[2], "password": r[3], "strength": r[4]}
        for r in rows
    ]

@app.delete("/api/credentials/{cred_id}")
def delete_credential(cred_id: int, user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM credentials WHERE id=%s AND user_id=%s", (cred_id, user_id))

    conn.commit()
    conn.close()

    return {"success": True}

# ================== NOTES ==================
@app.post("/api/notes")
def add_note(note: Note, user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO notes (user_id, title, content)
        VALUES (%s, %s, %s)
        RETURNING id
    """, (user_id, note.title, note.content))

    note_id = cur.fetchone()[0]
    conn.commit()
    conn.close()

    return {"id": note_id}

@app.get("/api/notes")
def get_notes(user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, title, content FROM notes WHERE user_id=%s", (user_id,))
    rows = cur.fetchall()

    conn.close()

    return [{"id": r[0], "title": r[1], "content": r[2]} for r in rows]
