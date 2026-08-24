"""
Auth for the DFIR platform, matching the existing JSON /api/... style rather
than server-rendered forms, since the frontend is a single-page fetch()-based
app.

- SQLite user table, bcrypt password hashing, signed session cookie (set via
  Starlette's SessionMiddleware, wired up in main.py).
- require_user() is a FastAPI dependency: raises 401 if there's no valid
  session, so protected /api/... routes just add `user: User = Depends(require_user)`.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from database import Base, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
router = APIRouter(prefix="/api/auth", tags=["auth"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=_now)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def get_current_user(request: Request, db: Session) -> "User | None":
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    """FastAPI dependency: 401s if there's no logged-in user. Use on every
    protected /api/... route."""
    user = get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


# --- request/response schemas ---

class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class UserOut(BaseModel):
    id: int
    username: str


# --- routes ---

@router.post("/register", response_model=UserOut)
def register(creds: Credentials, request: Request, db: Session = Depends(get_db)):
    username = creds.username.strip()
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="That username is already taken.")

    user = User(username=username, password_hash=hash_password(creds.password))
    db.add(user)
    db.commit()
    db.refresh(user)

    request.session["user_id"] = user.id
    return UserOut(id=user.id, username=user.username)


@router.post("/login", response_model=UserOut)
def login(creds: Credentials, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == creds.username.strip()).first()
    if not user or not verify_password(creds.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    request.session["user_id"] = user.id
    return UserOut(id=user.id, username=user.username)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(require_user)):
    return UserOut(id=user.id, username=user.username)
