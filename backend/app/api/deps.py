"""
API dependencies
"""
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import User
from app.core.security import get_current_user, get_current_superuser


# Database session dependency
DBSession = Depends(get_db)

# Current user dependency
CurrentUser = Depends(get_current_user)

# Superuser dependency
SuperUser = Depends(get_current_superuser)
