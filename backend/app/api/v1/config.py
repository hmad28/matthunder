"""
Configuration API routes - BYOK (Bring Your Own Key)
"""
import json
import httpx
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict

from app.config import settings

router = APIRouter(prefix="/config", tags=["configuration"])

CONFIG_FILE = Path(__file__).parent.parent.parent.parent / "ai_config.json"


class ProviderConfig(BaseModel):
    """AI provider configuration"""
    base_url: str = ""
    api_key: str = ""
    model: str = ""


class ConfigUpdateRequest(BaseModel):
    """Configuration update request"""
    providers: Dict[str, ProviderConfig] = {}


class TestConnectionRequest(BaseModel):
    """Test connection request"""
    base_url: str = Field(..., description="Base URL")
    api_key: str = ""
    model: str = Field(default="gpt-4o-mini", description="Model name")


def _load_ai_config() -> dict:
    """Load AI config from JSON file"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
        except:
            return {}
    return {}


def _save_ai_config(config: dict) -> None:
    """Save AI config to JSON file"""
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding='utf-8')


@router.get("/")
async def get_config():
    """Get current configuration"""
    ai_config = _load_ai_config()
    custom = ai_config.get("custom", {})
    
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "debug": settings.DEBUG,
        "ai_providers": {
            "custom": {
                "configured": bool(custom.get("base_url")),
                "base_url": custom.get("base_url", ""),
                "model": custom.get("model", "")
            }
        }
    }


@router.post("/update")
async def update_config(request: ConfigUpdateRequest):
    """Update AI provider configuration"""
    if not request.providers:
        raise HTTPException(status_code=400, detail="No providers in request")

    _save_ai_config(request.providers.dict())
    
    return {
        "message": "Configuration saved! Restart server to apply changes.",
        "providers_updated": list(request.providers.keys())
    }


@router.post("/test")
async def test_connection(request: TestConnectionRequest):
    """Test AI provider connection"""
    if not request.base_url:
        raise HTTPException(status_code=400, detail="Base URL required")

    # Try chat completions endpoint (OpenAI-compatible)
    url = request.base_url.rstrip('/')
    chat_url = f"{url}/chat/completions"
    
    headers = {"Content-Type": "application/json"}
    if request.api_key:
        headers["Authorization"] = f"Bearer {request.api_key}"
    
    payload = {
        "model": request.model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 5
    }
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(chat_url, json=payload, headers=headers)
            
            if response.status_code == 200:
                return {
                    "status": "ok",
                    "message": "Connection successful",
                    "provider": chat_url
                }
            elif response.status_code == 401:
                raise HTTPException(status_code=400, detail="Invalid API key")
            elif response.status_code == 404:
                # Try without /chat/completions
                response = await client.post(
                    url, json=payload, headers=headers
                )
                if response.status_code == 200:
                    return {
                        "status": "ok",
                        "message": "Connection successful (direct endpoint)",
                        "provider": url
                    }
                raise HTTPException(status_code=400, detail=f"Endpoint not found: {response.status_code}")
            else:
                detail = response.text[:200]
                raise HTTPException(status_code=400, detail=f"Connection failed ({response.status_code}): {detail}")
                
        except httpx.TimeoutException:
            raise HTTPException(status_code=400, detail="Connection timeout - check URL")
        except httpx.ConnectError:
            raise HTTPException(status_code=400, detail="Cannot connect - check URL and network")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Connection failed: {str(e)}")