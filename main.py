from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, constr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import sqlite3
import time
from collections import defaultdict
import os

SECRET_KEY = "vibe-production-secret-change-me-2026"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

DB_PATH = os.environ.get("DB_PATH", "vibe.db")
rate_limit = defaultdict(list)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            hashed_password TEXT,
            is_admin INTEGER DEFAULT 0,
            bio TEXT DEFAULT '',
            avatar TEXT DEFAULT '',
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            content TEXT,
            created_at TEXT,
            likes INTEGER DEFAULT 0,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            username TEXT,
            text TEXT,
            created_at TEXT,
            FOREIGN KEY (post_id) REFERENCES posts(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

app = FastAPI(title="Vibe API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def check_rate_limit(ip: str, limit: int = 10, window: int = 60):
    now = time.time()
    rate_limit[ip] = [t for t in rate_limit[ip] if now - t < window]
    if len(rate_limit[ip]) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests")
    rate_limit[ip].append(now)

class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=20)
    email: EmailStr
    password: constr(min_length=8)

class Token(BaseModel):
    access_token: str
    token_type: str

class PostCreate(BaseModel):
    content: constr(min_length=1, max_length=500)

class CommentCreate(BaseModel):
    text: constr(min_length=1, max_length=300)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if not user:
            raise credentials_exception
        return dict(user)
    except JWTError:
        raise credentials_exception

@app.post("/register")
async def register(user: UserCreate, request: Request):
    check_rate_limit(request.client.host)
    conn = get_db()
    existing = conn.execute("SELECT username FROM users WHERE username = ?", (user.username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already registered")
    conn.execute(
        "INSERT INTO users (username, email, hashed_password, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
        (user.username, user.email, get_password_hash(user.password), 1 if user.username == "admin" else 0, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return {"username": user.username, "email": user.email}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    if request:
        check_rate_limit(request.client.host, limit=5)
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (form_data.username,)).fetchone()
    conn.close()
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "is_admin": bool(current_user["is_admin"]),
        "bio": current_user["bio"],
        "avatar": current_user["avatar"]
    }

@app.post("/posts")
async def create_post(post: PostCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO posts (username, content, created_at) VALUES (?, ?, ?)",
        (current_user["username"], post.content, datetime.utcnow().isoformat())
    )
    conn.commit()
    post_id = cur.lastrowid
    conn.close()
    return {"id": post_id, "username": current_user["username"], "content": post.content}

@app.get("/posts")
async def get_posts(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    posts = conn.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    result = []
    for p in posts:
        comments = conn.execute("SELECT username, text FROM comments WHERE post_id = ? ORDER BY id", (p["id"],)).fetchall()
        result.append({
            "id": p["id"],
            "username": p["username"],
            "content": p["content"],
            "created_at": p["created_at"],
            "likes": p["likes"],
            "comments": [dict(c) for c in comments]
        })
    conn.close()
    return result

@app.post("/posts/{post_id}/like")
async def like_post(post_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    conn.execute("UPDATE posts SET likes = likes + 1 WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.post("/posts/{post_id}/comments")
async def add_comment(post_id: int, comment: CommentCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    conn.execute(
        "INSERT INTO comments (post_id, username, text, created_at) VALUES (?, ?, ?, ?)",
        (post_id, current_user["username"], comment.text, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/")
async def root():
    return {"status": "Vibe API online (SQLite)", "docs": "/docs"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
