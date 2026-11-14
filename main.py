from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, constr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict
import time
from collections import defaultdict

SECRET_KEY = "vibe-production-secret-change-me-2026"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory (trocar por DB depois)
users_db: Dict[str, dict] = {}
posts_db = []
rate_limit: Dict[str, list] = defaultdict(list)

app = FastAPI(title="Vibe API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

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
        if username is None or username not in users_db:
            raise credentials_exception
        return users_db[username]
    except JWTError:
        raise credentials_exception

@app.post("/register")
async def register(user: UserCreate, request: Request):
    check_rate_limit(request.client.host)
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    users_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "hashed_password": get_password_hash(user.password),
        "is_admin": user.username == "admin",
    }
    return {"username": user.username, "email": user.email}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    if request:
        check_rate_limit(request.client.host, limit=5)
    user = users_db.get(form_data.username)
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
        "is_admin": current_user.get("is_admin", False)
    }

@app.post("/posts")
async def create_post(post: PostCreate, current_user: dict = Depends(get_current_user)):
    new_post = {
        "id": len(posts_db) + 1,
        "username": current_user["username"],
        "content": post.content,
        "created_at": datetime.utcnow().isoformat(),
        "likes": 0
    }
    posts_db.append(new_post)
    return new_post

@app.get("/posts")
async def get_posts(current_user: dict = Depends(get_current_user)):
    return posts_db[::-1]

@app.get("/")
async def root():
    return {"status": "Vibe API online", "docs": "/docs"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
