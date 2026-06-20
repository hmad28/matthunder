"""
Configuration API routes
"""
from fastapi import APIRouter, Depends
from app.config import settings
from app.core.security import get_current_user
from app.models import User

router = APIRouter(prefix="/config", tags=["configuration"])


@router.get("/")
async def get_config(
    current_user: User = Depends(get_current_user)
):
    """Get current configuration (excluding sensitive data)"""
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "debug": settings.DEBUG,
        "katana_limit": settings.KATANA_LIMIT,
        "scan_speed": settings.SCAN_SPEED,
        "scan_timeout": settings.SCAN_TIMEOUT,
        "upload_dir": settings.UPLOAD_DIR,
        "reports_dir": settings.REPORTS_DIR,
        "scans_dir": settings.SCANS_DIR,
        "ai_providers": {
            "openai": bool(settings.OPENAI_API_KEY),
            "anthropic": bool(settings.ANTHROPIC_API_KEY),
            "gemini": bool(settings.GEMINI_API_KEY),
            "openrouter": bool(settings.OPENROUTER_API_KEY),
        },
        "acunetix_configured": bool(settings.ACUNETIX_URL and settings.ACUNETIX_API_KEY),
    }


@router.get("/output-dirs")
async def get_output_dirs(
    current_user: User = Depends(get_current_user)
):
    """Get output directory information"""
    import os
    from pathlib import Path
    
    dirs = {
        "uploads": str(Path(settings.UPLOAD_DIR).absolute()),
        "reports": str(Path(settings.REPORTS_DIR).absolute()),
        "scans": str(Path(settings.SCANS_DIR).absolute()),
    }
    
    # Check if directories exist and get file counts
    result = {}
    for name, path in dirs.items():
        exists = os.path.exists(path)
        file_count = 0
        if exists:
            file_count = len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
        result[name] = {
            "path": path,
            "exists": exists,
            "file_count": file_count
        }
    
    return result
