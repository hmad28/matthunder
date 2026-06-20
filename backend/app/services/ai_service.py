"""
AI Service - Business logic for AI operations
"""
from uuid import UUID
from typing import Optional
import json
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import AIAnalysis, Scan
from app.schemas import AIProviderInfo, AIAnalyzeResponse
from app.config import settings
from app.core.exceptions import NotFoundException, BadRequestException
from app.core.logging import get_logger

logger = get_logger(__name__)


class AIService:
    """Service for AI operations"""
    
    PROVIDERS = {
        "openai": {
            "name": "openai",
            "default_model": "gpt-4o-mini",
            "available_models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
            "api_url": "https://api.openai.com/v1/chat/completions",
            "env_key": "OPENAI_API_KEY"
        },
        "anthropic": {
            "name": "anthropic",
            "default_model": "claude-3-5-haiku-latest",
            "available_models": ["claude-3-5-sonnet-latest", "claude-3-5-haiku-latest", "claude-3-opus-latest"],
            "api_url": "https://api.anthropic.com/v1/messages",
            "env_key": "ANTHROPIC_API_KEY"
        },
        "gemini": {
            "name": "gemini",
            "default_model": "gemini-1.5-flash",
            "available_models": ["gemini-1.5-pro", "gemini-1.5-flash"],
            "api_url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            "env_key": "GEMINI_API_KEY"
        },
        "openrouter": {
            "name": "openrouter",
            "default_model": "meta-llama/llama-3.1-8b-instruct",
            "available_models": ["meta-llama/llama-3.1-8b-instruct", "anthropic/claude-3.5-sonnet", "openai/gpt-4o"],
            "api_url": "https://openrouter.ai/api/v1/chat/completions",
            "env_key": "OPENROUTER_API_KEY"
        }
    }
    
    @staticmethod
    def get_available_providers() -> list[AIProviderInfo]:
        """Get list of available AI providers"""
        providers = []
        
        for name, config in AIService.PROVIDERS.items():
            api_key = getattr(settings, config["env_key"], None)
            providers.append(AIProviderInfo(
                name=name,
                configured=bool(api_key),
                default_model=config["default_model"],
                available_models=config["available_models"]
            ))
        
        return providers
    
    @staticmethod
    async def analyze(
        prompt: str,
        provider: Optional[str],
        model: Optional[str],
        scan_id: Optional[UUID],
        user_id: UUID,
        db: AsyncSession
    ) -> AIAnalyzeResponse:
        """Run AI analysis on a prompt"""
        # Auto-detect provider if not specified
        if not provider:
            provider = AIService._detect_provider()
        
        if not provider or provider not in AIService.PROVIDERS:
            raise BadRequestException("No AI provider configured")
        
        provider_config = AIService.PROVIDERS[provider]
        api_key = getattr(settings, provider_config["env_key"], None)
        
        if not api_key:
            raise BadRequestException(f"{provider} API key not configured")
        
        model = model or provider_config["default_model"]
        
        # Call AI provider
        try:
            response_data = await AIService._call_provider(provider, api_key, model, prompt)
        except Exception as e:
            logger.error("ai_call_failed", provider=provider, error=str(e))
            raise BadRequestException(f"AI provider call failed: {str(e)}")
        
        # Save analysis result
        analysis = AIAnalysis(
            scan_id=scan_id,
            provider=provider,
            model=model,
            prompt=prompt,
            response=response_data,
            tokens_used=response_data.get("tokens_used"),
            cost_usd=response_data.get("cost_usd")
        )
        db.add(analysis)
        await db.commit()
        await db.refresh(analysis)
        
        logger.info("ai_analysis_completed", provider=provider, model=model)
        
        return AIAnalyzeResponse(
            id=analysis.id,
            provider=provider,
            model=model,
            response=response_data,
            tokens_used=analysis.tokens_used,
            created_at=analysis.created_at
        )
    
    @staticmethod
    async def hunt(
        target_id: UUID,
        provider: Optional[str],
        model: Optional[str],
        focus: Optional[str],
        user_id: UUID,
        db: AsyncSession
    ) -> dict:
        """Run AI-powered vulnerability hunting"""
        # Get target's findings
        from sqlalchemy import select
        from app.models import Target, Finding
        
        result = await db.execute(select(Target).where(Target.id == target_id))
        target = result.scalar_one_or_none()
        
        if not target:
            raise NotFoundException("Target not found")
        
        # Get recent findings for this target
        result = await db.execute(
            select(Finding)
            .join(Scan)
            .where(Scan.target_id == target_id)
            .order_by(Finding.created_at.desc())
            .limit(50)
        )
        findings = result.scalars().all()
        
        # Build prompt
        prompt = f"""Analyze the following security findings for {target.domain} and provide:
1. Critical vulnerabilities that need immediate attention
2. Potential attack chains
3. Remediation priorities
4. False positive assessment

Findings:
{json.dumps([{"scanner": f.scanner, "severity": f.severity, "title": f.title, "url": f.url} for f in findings], indent=2)}

{f"Focus on: {focus}" if focus else ""}

Provide your analysis in JSON format with keys: critical_issues, attack_chains, remediation_priority, false_positives"""
        
        # Run AI analysis
        analysis = await AIService.analyze(prompt, provider, model, None, user_id, db)
        
        return {
            "target": target.domain,
            "findings_count": len(findings),
            "analysis": analysis.response,
            "analysis_id": str(analysis.id)
        }
    
    @staticmethod
    def _detect_provider() -> Optional[str]:
        """Auto-detect available provider"""
        for provider, config in AIService.PROVIDERS.items():
            if getattr(settings, config["env_key"], None):
                return provider
        return None
    
    @staticmethod
    async def _call_provider(
        provider: str,
        api_key: str,
        model: str,
        prompt: str
    ) -> dict:
        """Call AI provider API"""
        async with httpx.AsyncClient(timeout=60.0) as client:
            if provider == "openai":
                response = await client.post(
                    AIService.PROVIDERS["openai"]["api_url"],
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.7
                    }
                )
                data = response.json()
                return {
                    "content": data["choices"][0]["message"]["content"],
                    "tokens_used": data.get("usage", {}).get("total_tokens"),
                    "model": model
                }
            
            elif provider == "anthropic":
                response = await client.post(
                    AIService.PROVIDERS["anthropic"]["api_url"],
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model,
                        "max_tokens": 4096,
                        "messages": [{"role": "user", "content": prompt}]
                    }
                )
                data = response.json()
                return {
                    "content": data["content"][0]["text"],
                    "tokens_used": data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0),
                    "model": model
                }
            
            elif provider == "gemini":
                url = AIService.PROVIDERS["gemini"]["api_url"].format(model=model)
                response = await client.post(
                    f"{url}?key={api_key}",
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}]
                    }
                )
                data = response.json()
                return {
                    "content": data["candidates"][0]["content"]["parts"][0]["text"],
                    "tokens_used": data.get("usageMetadata", {}).get("totalTokenCount"),
                    "model": model
                }
            
            elif provider == "openrouter":
                response = await client.post(
                    AIService.PROVIDERS["openrouter"]["api_url"],
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://github.com/hmad28/matthunder"
                    },
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}]
                    }
                )
                data = response.json()
                return {
                    "content": data["choices"][0]["message"]["content"],
                    "tokens_used": data.get("usage", {}).get("total_tokens"),
                    "model": model
                }
            
            else:
                raise BadRequestException(f"Unknown provider: {provider}")
