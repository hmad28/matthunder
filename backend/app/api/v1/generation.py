"""
Generation API routes - Chain-of-Thought and BOAZ-MCP
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Optional

from app.schemas import FindingResponse
from app.models import Finding
from app.database import get_db
from app.generation import ChainOfThought, BOAZMCP, PromptBuilder, ResponseParser
from app.memory import async_updater

router = APIRouter(prefix="/generation", tags=["generation"])


class CoTRequest(BaseModel):
    """Request for Chain-of-Thought generation"""
    target_id: str = Field(..., description="Target domain or ID")
    scan_id: str = Field(..., description="Scan session ID")
    finding_type: str = Field(..., description="Type of finding")
    reconnaissance_data: dict = Field(default_factory=dict, description="Reconnaissance data")
    context: Optional[dict] = Field(None, description="Context from memory")


class BOAZMCPRequest(BaseModel):
    """Request for BOAZ-MCP payload generation"""
    target_url: str = Field(..., description="Target URL")
    vulnerability_type: str = Field(..., description="Type of vulnerability")
    context: dict = Field(default_factory=dict, description="Reconnaissance context")
    evasion_techniques: List[str] = Field(default_factory=list, description="Evasion techniques")
    language: str = Field(default="bash", description="Payload language")
    stealth_mode: bool = Field(default=True, description="Enable stealth mode")


# Initialize generators
chain_of_thought = ChainOfThought(ai_service=None)  # Would inject actual AI service
boaz_mcp = BOAZMCP(mcp_executor=None)  # Would inject actual MCP executor
prompt_builder = PromptBuilder()
response_parser = ResponseParser()


@router.post("/cot")
async def generate_cot(request: CoTRequest):
    """Generate Chain-of-Thought for pentesting"""
    # Get context from memory
    context = await async_updater.get_session_summary(request.scan_id)

    response = await chain_of_thought.generate_thought_chain(request)

    return {
        "target_id": request.target_id,
        "scan_id": request.scan_id,
        "finding_type": request.finding_type,
        "cot_response": {
            "thought_chain": response.thought_chain,
            "next_action": response.next_action,
            "reasoning_summary": response.reasoning_summary,
            "confidence": response.confidence,
            "timestamp": response.timestamp
        },
        "context": context
    }


@router.post("/boaz-mcp")
async def generate_boaz_mcp(request: BOAZMCPRequest):
    """Generate payload using BOAZ-MCP"""
    response = await boaz_mcp.generate_payload(request)

    return {
        "payload": response.payload,
        "payload_type": response.payload_type,
        "evasion_techniques": response.evasion_techniques_applied,
        "detection_evasion_score": response.detection_evasion_score,
        "stealth_score": response.stealth_score,
        "timestamp": response.timestamp
    }


@router.get("/prompt/available")
async def get_available_prompts():
    """Get list of available prompt types"""
    return {
        "prompts": prompt_builder.get_available_prompts()
    }


@router.post("/prompt/build")
async def build_prompt(request: dict):
    """Build a custom prompt"""
    prompt_type = request.get("type")
    parameters = request.get("parameters", {})

    if prompt_type == "ouroboros":
        prompt = prompt_builder.build_ouroboros_prompt(
            target_id=parameters.get("target_id"),
            current_task=parameters.get("current_task")
        )
    elif prompt_type == "reasoning":
        prompt = prompt_builder.build_reasoning_prompt(
            target_id=parameters.get("target_id"),
            finding_type=parameters.get("finding_type"),
            context=parameters.get("context")
        )
    elif prompt_type == "payload":
        prompt = prompt_builder.build_payload_prompt(
            target_url=parameters.get("target_url"),
            vulnerability_type=parameters.get("vulnerability_type"),
            language=parameters.get("language"),
            context=parameters.get("context")
        )
    elif prompt_type == "validation":
        prompt = prompt_builder.build_validation_prompt(
            findings=parameters.get("findings"),
            context=parameters.get("context")
        )
    elif prompt_type == "summary":
        prompt = prompt_builder.build_summary_prompt(
            scan_id=parameters.get("scan_id"),
            target_id=parameters.get("target_id"),
            findings_count=parameters.get("findings_count"),
            status=parameters.get("status")
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown prompt type: {prompt_type}"
        )

    return {
        "prompt_type": prompt_type,
        "prompt": prompt
    }


@router.post("/parse")
async def parse_response(request: dict):
    """Parse AI response"""
    response_text = request.get("response")
    expected_format = request.get("format", "json")

    parsed = response_parser.parse_response(response_text, expected_format)

    return parsed


@router.post("/validate-response")
async def validate_response(request: dict):
    """Validate AI response against rules"""
    response_text = request.get("response")
    validation_rules = request.get("validation_rules", {})

    validation_result = response_parser.validate_response(response_text, validation_rules)

    return validation_result


@router.get("/payload/available-languages")
async def get_payload_languages():
    """Get list of available payload languages"""
    return {
        "languages": boaz_mcp.get_supported_languages()
    }


@router.get("/payload/available-types")
async def get_payload_types():
    """Get list of available payload types"""
    return {
        "attack_types": boaz_mcp.get_supported_attack_types()
    }


@router.get("/payload/evasion-techniques")
async def get_evasion_techniques():
    """Get list of evasion techniques"""
    return {
        "evasion_techniques": boaz_mcp.get_evasion_techniques()
    }


@router.post("/payload/evaluate-safety")
async def evaluate_payload_safety(request: dict):
    """Evaluate payload safety for authorized testing"""
    payload = request.get("payload")
    context = request.get("context")

    safety_result = await boaz_mcp.evaluate_payload_safety(payload, context)

    return safety_result