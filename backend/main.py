import sqlite3
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bcrypt

app = FastAPI()

# Enable CORS for frontend connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Request schemas
class UserSignUp(BaseModel):
    username: str
    password: str
    phone: str
    email: str | None = None

class UserLogin(BaseModel):
    username: str
    password: str

# Helper functions for password hashing
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# --- API Routes ---

# 1. Sign Up API
@app.post("/api/signup")
def signup(user: UserSignUp):
    hashed = hash_password(user.password)
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password, phone, email) VALUES (?, ?, ?, ?)",
            (user.username, hashed, user.phone, user.email)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists!"
        )
    finally:
        conn.close()
        
    return {"message": "User registered successfully"}

# 2. Login API
@app.post("/api/login")
def login(user: UserLogin):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT password FROM users WHERE username = ?", (user.username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password!"
        )
        
    hashed_pwd = row[0]
    if not verify_password(user.password, hashed_pwd):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password!"
        )
        
    return {"message": "Login successful"}