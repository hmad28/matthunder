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


@router.post("/hunt")
async def ai_hunt(body: dict):
    """AI-powered automated vulnerability hunting.

    Given a target domain, the AI performs a multi-stage analysis:
    1. Reconnaissance — what technologies, endpoints, and attack surface exist
    2. Hypothesis — what vulnerabilities are likely based on tech stack
    3. Validation — how to test each hypothesis
    4. Report — structured findings with severity

    Body: {"domain": "example.com", "provider": "openai", "model": "gpt-4o-mini"}
    """
    domain = body.get("domain", "").strip().lower()
    provider = body.get("provider", "openai").strip().lower()
    model = body.get("model", "")

    if not domain:
        raise HTTPException(status_code=400, detail="domain required")

    info = AI_LABELS.get(provider)
    if not info:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    label, env_key, default_models = info
    api_key = os.environ.get(env_key, "")
    if not api_key:
        raise HTTPException(status_code=400, detail=f"{label} API key not configured")
    if not model:
        model = default_models[0]

    prompt = f"""You are an expert security researcher performing a bug bounty hunting assessment on {domain}.

Perform a comprehensive vulnerability analysis following these steps:

1. **RECONNAISSANCE**: Based on the domain {domain}, identify:
   - Likely technologies and frameworks used
   - Common subdomains and endpoints to check
   - Potential attack surface areas

2. **VULNERABILITY HYPOTHESIS**: For each attack surface area, list specific vulnerabilities that are likely to exist, including:
   - OWASP Top 10 categories
   - Common misconfigurations for the identified technologies
   - Known CVEs for popular frameworks used by {domain}

3. **TESTING METHODOLOGY**: For each hypothesized vulnerability, provide:
   - Specific payloads or techniques to test
   - Tools that can be used (curl, nuclei, custom scripts)
   - Indicators of successful exploitation

4. **FINDINGS REPORT**: Output findings in this exact JSON format at the end:
```json
{{
  "findings": [
    {{
      "title": "Short vulnerability title",
      "severity": "critical|high|medium|low|info",
      "category": "sqli|xss|ssrf|lfi|ssti|idor|auth|config|misconfig|other",
      "description": "Detailed description of the vulnerability",
      "remediation": "How to fix this issue",
      "endpoints": ["likely endpoint URLs"],
      "cve": "CVE number if applicable or null",
      "likelihood": "high|medium|low"
    }}
  ]
}}
```

Focus on HIGH and CRITICAL findings. Be specific to {domain} — do NOT give generic advice.
Limit to the top 8 most impactful findings.
"""

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

        # Try to extract JSON from the result
        import re, json
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', result)
        parsed = None
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        if not parsed:
            try:
                parsed = json.loads(result)
            except json.JSONDecodeError:
                parsed = None

        return {
            "result": result,
            "parsed": parsed,
            "provider": provider,
            "model": model,
            "domain": domain,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
