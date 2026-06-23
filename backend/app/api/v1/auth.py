"""
Authentication API routes - Enhanced with refresh tokens and API keys
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.schemas import UserCreate, UserResponse, Token, APIKeyCreate, APIKeyResponse, APIKeyCreateResponse
from app.models import User
from app.database import get_db
from app.core.security import get_password_hash, get_current_user
from app.services.auth_service import AuthService
from app.core.exceptions import ConflictException, UnauthorizedException

router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBasic()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user"""
    # Check if username exists
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise ConflictException("Username already registered")
    
    # Check if email exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise ConflictException("Email already registered")
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password)
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    return user


@router.post("/login")
async def login(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return access + refresh tokens.
    
    Use HTTP Basic Auth with username and password.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    
    result = await AuthService.login(
        db, credentials.username, credentials.password, ip_address, user_agent
    )
    
    if not result:
        raise UnauthorizedException("Invalid credentials")
    
    return result


@router.post("/refresh")
async def refresh_token(
    request: Request,
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using a valid refresh token.
    
    Returns new access token and new refresh token (rotation).
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    
    result = await AuthService.rotate_refresh_token(db, refresh_token, ip_address, user_agent)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    new_access_token, new_refresh_token, _ = result
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": 30 * 60,
    }


@router.post("/logout")
async def logout(
    refresh_token: str = None,
    all_devices: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Logout user by revoking refresh tokens.
    
    If refresh_token is provided, revoke that specific token.
    If all_devices is True, revoke all tokens for the user.
    """
    if all_devices:
        count = await AuthService.revoke_all_user_tokens(db, current_user.id)
        return {"message": f"Revoked {count} tokens", "all_devices": True}
    
    if refresh_token:
        success = await AuthService.revoke_refresh_token(db, refresh_token)
        if not success:
            raise HTTPException(status_code=400, detail="Invalid refresh token")
        return {"message": "Token revoked", "all_devices": False}
    
    raise HTTPException(status_code=400, detail="Provide refresh_token or set all_devices=true")


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info"""
    return current_user


# ---- API Key Management ----

@router.post("/api-keys", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_data: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new API key for service accounts (CLI, bot, integrations).
    
    The key is returned only once on creation. Store it securely.
    """
    raw_key, api_key = await AuthService.create_api_key(
        db, current_user.id, key_data.name, key_data.scopes, key_data.expires_in_days
    )
    
    response = APIKeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        scopes=api_key.scopes,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        key=raw_key,
    )
    return response


@router.get("/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all API keys for current user"""
    keys = await AuthService.list_api_keys(db, current_user.id)
    return keys


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Revoke an API key"""
    success = await AuthService.revoke_api_key(db, key_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"message": "API key revoked"}
