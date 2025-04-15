from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os
from dotenv import load_dotenv

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
import user_repository
import db
import authorization

# Load environment variables
load_dotenv()

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Token and user models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class UserInDB(BaseModel):
    id: int
    full_name: str
    email: str
    password: str
    profile: Optional[str] = None
    role: str

# Password verification and hashing
def verify_password(plain_password, hashed_password):
    """
    Verify a password against a hash
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """
    Hash a password
    """
    return pwd_context.hash(password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None):
    """
    Create a JWT token
    """
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    
    # Create JWT token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt

def store_token(user_id: int, token: str, expires_at: datetime):
    """
    Store a token in the database
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO user_sessions (user_id, token, expires_at) VALUES (%s, %s, %s)",
            (user_id, token, expires_at)
        )
        conn.commit()
        result = True
    except Exception as e:
        conn.rollback()
        print(f"Error storing token: {e}")
        result = False
    finally:
        cursor.close()
        conn.close()
    
    return result

def invalidate_token(token: str):
    """
    Invalidate a token by deleting it from the database
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM user_sessions WHERE token = %s", (token,))
        conn.commit()
        result = True
    except Exception as e:
        conn.rollback()
        print(f"Error invalidating token: {e}")
        result = False
    finally:
        cursor.close()
        conn.close()
    
    return result

def is_token_valid(token: str):
    """
    Check if a token is valid (exists in the database and is not expired)
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT expires_at FROM user_sessions 
            WHERE token = %s AND expires_at > NOW()
        """, (token,))
        result = cursor.fetchone() is not None
    except Exception as e:
        print(f"Error checking token validity: {e}")
        result = False
    finally:
        cursor.close()
        conn.close()
    
    return result

async def authenticate_user(email: str, password: str):
    """
    Authenticate a user with email and password
    """
    user = user_repository.get_user_by_email(email)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Get the current user from the JWT token
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Check if token exists in the database
    if not is_token_valid(token):
        raise credentials_exception
    
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        role: str = payload.get("role", "user")
        
        if email is None:
            raise credentials_exception
        
        token_data = TokenData(username=email, role=role)
    except JWTError:
        raise credentials_exception
    
    # Get user from database
    user = user_repository.get_user_by_email(email=token_data.username)
    if user is None:
        raise credentials_exception
    
    return user

async def get_current_active_user(current_user = Depends(get_current_user)):
    """
    Get the current active user (used as a dependency in routes)
    """
    return current_user

def check_admin_role(user: dict):
    """
    Check if a user has the admin role
    """
    return user.get("role") == "admin"

def authorize_user(user_id: int, user_role: str, action: str, resource_id: Optional[int] = None, owner_id: Optional[int] = None):
    """
    Authorize a user to perform an action using Oso
    """
    return authorization.authorize(user_id, user_role, action, resource_id, owner_id)

def get_permissions_for_role(role: str):
    """
    Get all permissions for a role
    """
    return authorization.get_user_permissions(role) 