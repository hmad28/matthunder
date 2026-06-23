"""
Enhanced Authentication Service - JWT + Refresh Tokens + API Keys

Provides production-safe authentication with:
- Short-lived access tokens (JWT)
- Long-lived refresh tokens (stored in DB, rotatable)
- API keys for service accounts (CLI, bot, integrations)
- Token revocation support
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.config import settings
from app.models import User, RefreshToken, APIKey
from app.services.audit_service import log_auth_login


class AuthService:
    """Enhanced authentication service"""
    
    # ---- Access Token (JWT) ----
    
    @staticmethod
    def create_access_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
        """Create a short-lived JWT access token"""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode = {
            "sub": user_id,
            "exp": expire,
            "type": "access",
            "iat": datetime.utcnow(),
        }
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    @staticmethod
    def verify_access_token(token: str) -> Optional[str]:
        """Verify JWT access token and return user_id"""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            if payload.get("type") != "access":
                return None
            user_id = payload.get("sub")
            if user_id is None:
                return None
            # Check expiration explicitly
            if payload.get("exp") and datetime.utcnow() > datetime.utcfromtimestamp(payload["exp"]):
                return None
            return user_id
        except JWTError:
            return None
    
    # ---- Refresh Token ----
    
    @staticmethod
    def _hash_refresh_token(token: str) -> str:
        """Hash a refresh token for storage"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    @staticmethod
    async def create_refresh_token(
        db: AsyncSession,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        expires_days: int = 7,
    ) -> tuple[str, RefreshToken]:
        """
        Create a new refresh token.
        
        Returns:
            Tuple of (raw_token, RefreshToken model)
        """
        raw_token = secrets.token_urlsafe(64)
        token_hash = AuthService._hash_refresh_token(raw_token)
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        refresh_token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.add(refresh_token)
        await db.commit()
        await db.refresh(refresh_token)
        
        return raw_token, refresh_token
    
    @staticmethod
    async def verify_refresh_token(db: AsyncSession, raw_token: str) -> Optional[RefreshToken]:
        """
        Verify a refresh token and return the model.
        
        Returns None if token is invalid, expired, or revoked.
        """
        token_hash = AuthService._hash_refresh_token(raw_token)
        
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked == False,
                RefreshToken.expires_at > datetime.utcnow(),
            )
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def rotate_refresh_token(
        db: AsyncSession,
        raw_token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[tuple[str, str, RefreshToken]]:
        """
        Rotate a refresh token: invalidate old, create new.
        
        Returns:
            Tuple of (new_access_token, new_refresh_token, RefreshToken model)
            or None if the old token is invalid
        """
        old_token = await AuthService.verify_refresh_token(db, raw_token)
        if not old_token:
            return None
        
        # Revoke old token
        old_token.revoked = True
        old_token.revoked_at = datetime.utcnow()
        
        # Create new tokens
        user_id = old_token.user_id
        new_access_token = AuthService.create_access_token(user_id)
        new_raw_refresh, new_refresh_token = await AuthService.create_refresh_token(
            db, user_id, ip_address, user_agent
        )
        
        await db.commit()
        
        return new_access_token, new_raw_refresh, new_refresh_token
    
    @staticmethod
    async def revoke_refresh_token(db: AsyncSession, raw_token: str) -> bool:
        """Revoke a refresh token"""
        token_hash = AuthService._hash_refresh_token(raw_token)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        token = result.scalar_one_or_none()
        if not token:
            return False
        
        token.revoked = True
        token.revoked_at = datetime.utcnow()
        await db.commit()
        return True
    
    @staticmethod
    async def revoke_all_user_tokens(db: AsyncSession, user_id: str) -> int:
        """Revoke all refresh tokens for a user (logout everywhere)"""
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked == False,
            )
        )
        tokens = result.scalars().all()
        now = datetime.utcnow()
        for token in tokens:
            token.revoked = True
            token.revoked_at = now
        await db.commit()
        return len(tokens)
    
    @staticmethod
    async def cleanup_expired_tokens(db: AsyncSession) -> int:
        """Remove expired refresh tokens from database"""
        result = await db.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < datetime.utcnow())
        )
        await db.commit()
        return result.rowcount
    
    # ---- API Keys ----
    
    @staticmethod
    def _hash_api_key(key: str) -> str:
        """Hash an API key for storage"""
        return hashlib.sha256(key.encode()).hexdigest()
    
    @staticmethod
    async def create_api_key(
        db: AsyncSession,
        user_id: str,
        name: str,
        scopes: Optional[list[str]] = None,
        expires_in_days: Optional[int] = None,
    ) -> tuple[str, APIKey]:
        """
        Create a new API key.
        
        Returns:
            Tuple of (raw_key, APIKey model)
        """
        raw_key = f"mt_{secrets.token_urlsafe(48)}"
        key_hash = AuthService._hash_api_key(raw_key)
        
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        api_key = APIKey(
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            scopes=scopes or ["read", "write"],
            expires_at=expires_at,
        )
        db.add(api_key)
        await db.commit()
        await db.refresh(api_key)
        
        return raw_key, api_key
    
    @staticmethod
    async def verify_api_key(db: AsyncSession, raw_key: str) -> Optional[tuple[APIKey, User]]:
        """
        Verify an API key and return (APIKey, User) tuple.
        
        Returns None if key is invalid, expired, or inactive.
        """
        key_hash = AuthService._hash_api_key(raw_key)
        
        result = await db.execute(
            select(APIKey).where(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True,
            )
        )
        api_key = result.scalar_one_or_none()
        
        if not api_key:
            return None
        
        # Check expiration
        if api_key.expires_at and datetime.utcnow() > api_key.expires_at:
            return None
        
        # Get user
        user_result = await db.execute(select(User).where(User.id == api_key.user_id))
        user = user_result.scalar_one_or_none()
        
        if not user or not user.is_active:
            return None
        
        # Update last_used_at
        api_key.last_used_at = datetime.utcnow()
        await db.commit()
        
        return api_key, user
    
    @staticmethod
    async def revoke_api_key(db: AsyncSession, key_id: str, user_id: str) -> bool:
        """Revoke an API key"""
        result = await db.execute(
            select(APIKey).where(
                APIKey.id == key_id,
                APIKey.user_id == user_id,
            )
        )
        api_key = result.scalar_one_or_none()
        if not api_key:
            return False
        
        api_key.is_active = False
        await db.commit()
        return True
    
    @staticmethod
    async def list_api_keys(db: AsyncSession, user_id: str) -> list[APIKey]:
        """List all API keys for a user"""
        result = await db.execute(
            select(APIKey).where(APIKey.user_id == user_id).order_by(APIKey.created_at.desc())
        )
        return result.scalars().all()
    
    # ---- Login Flow ----
    
    @staticmethod
    async def login(
        db: AsyncSession,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Authenticate user and return access + refresh tokens.
        
        Returns:
            Dict with access_token, refresh_token, token_type, expires_in
            or None if authentication fails
        """
        from app.core.security import verify_password
        
        # Find user
        result = await db.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            await log_auth_login(db, "unknown", "password", ip_address, user_agent, "failure")
            return None
        
        if not verify_password(password, user.hashed_password):
            await log_auth_login(db, user.id, "password", ip_address, user_agent, "failure")
            return None
        
        if not user.is_active:
            await log_auth_login(db, user.id, "password", ip_address, user_agent, "failure")
            return None
        
        # Create tokens
        access_token = AuthService.create_access_token(user.id)
        raw_refresh_token, _ = await AuthService.create_refresh_token(
            db, user.id, ip_address, user_agent
        )
        
        await log_auth_login(db, user.id, "password", ip_address, user_agent, "success")
        
        return {
            "access_token": access_token,
            "refresh_token": raw_refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user_id": user.id,
        }
