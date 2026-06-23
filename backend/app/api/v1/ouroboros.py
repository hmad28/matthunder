"""
Ouroboros Persona API routes
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List

from app.ouroboros import PersonaEngine, PersonaConfig, InstructionEngine, ConstraintValidator, OutputFormatter

router = APIRouter(prefix="/ouroboros", tags=["ouroboros"])


class PersonaConfigUpdate(BaseModel):
    """Request for updating persona config"""
    enabled: Optional[bool] = None
    strict_mode: Optional[bool] = None
    enforcement_level: Optional[str] = None
    output_format: Optional[str] = None
    no_theoretical_bugs: Optional[bool] = None
    authentication_timeout: Optional[int] = None


class HypothesisRequest(BaseModel):
    """Request for generating cycle tick"""
    active_hypothesis: str
    target: str
    recommended_tool: str
    command_arguments: str
    confidence: float = Field(default=0.5, ge=0, le=1)


class SessionRequest(BaseModel):
    """Request for session management"""
    session_id: str
    target_id: str


# Initialize
config = PersonaConfig()
persona_engine = PersonaEngine(config=config)
instruction_engine = InstructionEngine(persona_engine)
constraint_validator = ConstraintValidator()
output_formatter = OutputFormatter()


@router.get("/persona")
async def get_persona():
    """Get current Ouroboros persona"""
    return {
        "config": config.dict(),
        "system_prompt": persona_engine.get_system_prompt("example.com")
    }


@router.put("/config")
async def update_persona_config(request: PersonaConfigUpdate):
    """Update persona configuration"""
    update_data = request.dict(exclude_none=True)
    for key, value in update_data.items():
        if hasattr(config, key):
            setattr(config, key, value)

    return {
        "message": "Config updated",
        "config": config.dict()
    }


@router.post("/session/start")
async def start_session(request: SessionRequest):
    """Start an Ouroboros session"""
    persona_engine.start_session(request.session_id, request.target_id)

    return {
        "session_id": request.session_id,
        "target_id": request.target_id,
        "system_prompt": persona_engine.get_system_prompt(request.target_id),
        "status": "started"
    }


@router.post("/session/end")
async def end_session(request: SessionRequest):
    """End an Ouroboros session"""
    session = persona_engine.end_session(request.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

    return session


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Get session info"""
    session = persona_engine.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

    return session


@router.get("/session/stats")
async def get_session_stats():
    """Get session statistics"""
    stats = persona_engine.get_session_statistics()
    return stats


@router.post("/cycle-tick")
async def generate_cycle_tick(request: HypothesisRequest):
    """Generate a JSON cycle tick"""
    hypothesis = {
        "active_hypothesis": request.active_hypothesis,
        "target": request.target,
        "recommended_tool": request.recommended_tool,
        "command_arguments": request.command_arguments,
        "confidence": request.confidence
    }

    cycle_tick = persona_engine.get_json_cycle_tick(hypothesis)

    return {
        "cycle_tick": cycle_tick,
        "schema": output_formatter.get_cycle_tick_schema()
    }


@router.post("/validate")
async def validate_output(request: dict):
    """Validate AI output against Ouroboros rules"""
    output = request.get("output", "")
    target_id = request.get("target_id", "")

    validation = persona_engine.validate_output(output)
    constraint_validation = constraint_validator.validate_output(output)

    scope_validation = {}
    if target_id:
        scope_validation = constraint_validator.validate_scope_compliance(target_id, output)

    return {
        "persona_validation": validation,
        "constraint_validation": constraint_validation,
        "scope_validation": scope_validation,
        "overall_valid": validation["valid"] and constraint_validation["valid"]
    }


@router.post("/format")
async def format_output(request: dict):
    """Format output according to persona rules"""
    output = request.get("output", "")
    format_type = request.get("format", "json")
    hypothesis = request.get("hypothesis")

    formatted = output_formatter.format_output(output, format_type, hypothesis)

    return {
        "formatted_output": formatted,
        "format": format_type
    }


@router.get("/prompts")
async def get_prompts(target_id: str):
    """Get Ouroboros prompts for a target"""
    system_prompt = persona_engine.get_system_prompt(target_id)
    instructions = instruction_engine.get_all_instructions(target_id)

    return {
        "system_prompt": system_prompt,
        "instructions": instructions,
        "instruction_count": len(instructions)
    }


@router.get("/instructions/{target_id}")
async def get_instructions(target_id: str):
    """Get instructions for a target"""
    summary = instruction_engine.get_instruction_summary(target_id)
    return summary


@router.post("/validate-evidence")
async def validate_evidence(request: dict):
    """Validate evidence quality"""
    evidence = request.get("evidence", {})
    quality = output_formatter.validate_evidence_quality(evidence)

    return quality


@router.get("/cycle-tick-schema")
async def get_cycle_tick_schema():
    """Get JSON cycle tick schema"""
    schema = output_formatter.get_cycle_tick_schema()
    return schema


@router.post("/format-finding")
async def format_finding(request: dict):
    """Format a finding report"""
    finding = request.get("finding", {})
    formatted = output_formatter.format_finding_report(finding)

    return {
        "formatted_report": formatted,
        "finding": finding
    }


@router.post("/validate-finding-report")
async def validate_finding_report(request: dict):
    """Validate finding report against Ouroboros rules"""
    report = request.get("report", {})
    validation = instruction_engine.validate_finding_report(report)
    return validation


@router.get("/config")
async def get_persona_config():
    """Get current persona configuration"""
    return config.dict()


@router.get("/validation-stats")
async def get_validation_stats():
    """Get constraint validation statistics"""
    stats = constraint_validator.get_validation_statistics()
    return stats