"""
web/api/ai.py — AI-powered analysis endpoints.
"""

import os
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/ai", tags=["ai"])

AI_LABELS = {
    "openai": ("OpenAI", "OPENAI_API_KEY", ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo"]),
    "anthropic": ("Anthropic", "ANTHROPIC_API_KEY", ["claude-3-5-haiku-latest", "claude-3-5-sonnet-latest"]),
    "gemini": ("Gemini", "GEMINI_API_KEY", ["gemini-1.5-flash", "gemini-1.5-pro"]),
    "openrouter": ("OpenRouter", "OPENROUTER_API_KEY", ["openai/gpt-4o-mini", "anthropic/claude-3.5-sonnet"]),
}


@router.get("/providers")
async def ai_providers():
    """List available AI providers and whether they're configured."""
    providers = []
    for key, (label, env_key, models) in AI_LABELS.items():
        val = os.environ.get(env_key, "")
        providers.append({
            "key": key,
            "label": label,
            "configured": bool(val),
            "masked": val[:8] + "..." if val and len(val) > 12 else (val[:4] + "..." if val else ""),
            "models": models,
        })
    return {"providers": providers}


@router.post("/analyze")
async def ai_analyze(body: dict):
    """Analyse text using a configured AI provider.

    Body: {"provider": "openai", "model": "gpt-4o-mini", "prompt": "..."}
    """
    provider = body.get("provider", "").lower().strip()
    model = body.get("model", "")
    prompt = body.get("prompt", "")
    if not provider or not prompt:
        raise HTTPException(status_code=400, detail="provider and prompt required")

    info = AI_LABELS.get(provider)
    if not info:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    label, env_key, default_models = info
    api_key = os.environ.get(env_key, "")
    if not api_key:
        raise HTTPException(status_code=400, detail=f"{label} API key not configured")

    if not model:
        model = default_models[0]

    try:
        if provider == "openai":
            result = _call_openai(api_key, model, prompt)
        elif provider == "anthropic":
            result = _call_anthropic(api_key, model, prompt)
        elif provider == "gemini":
            result = _call_gemini(api_key, model, prompt)
        elif provider == "openrouter":
            result = _call_openrouter(api_key, model, prompt)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
        return {"result": result, "provider": provider, "model": model}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _call_openai(key, model, prompt):
    import httpx
    r = httpx.post("https://api.openai.com/v1/chat/completions", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
    }, json={"model": model, "messages": [{"role": "user", "content": prompt}],
             "max_tokens": 4096}, timeout=120)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _call_anthropic(key, model, prompt):
    import httpx
    r = httpx.post("https://api.anthropic.com/v1/messages", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }, json={"model": model, "max_tokens": 4096,
             "messages": [{"role": "user", "content": prompt}]}, timeout=120)
    r.raise_for_status()
    return r.json()["content"][0]["text"]


def _call_gemini(key, model, prompt):
    import httpx
    r = httpx.post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}",
                   headers={"Content-Type": "application/json"},
                   json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=120)
    r.raise_for_status()
    return r.json()["candidates"][0]["content"]["parts"][0]["text"]


def _call_openrouter(key, model, prompt):
    import httpx
    r = httpx.post("https://openrouter.ai/api/v1/chat/completions", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
    }, json={"model": model, "messages": [{"role": "user", "content": prompt}],
             "max_tokens": 4096}, timeout=120)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]
