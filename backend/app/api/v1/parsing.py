"""
Parsing API routes - Log cleaning, evidence processing, and finding enrichment
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Optional

from app.parsing import LogCleaner, ContextReducer, EvidenceProcessor, FindingEnricher

router = APIRouter(prefix="/parsing", tags=["parsing"])


class CleanLogRequest(BaseModel):
    """Request for log cleaning"""
    raw_log: str = Field(..., description="Raw log output")
    log_type: str = Field(default="generic", description="Type of log")


class EnrichRequest(BaseModel):
    """Request for finding enrichment"""
    finding: dict = Field(..., description="Finding to enrich")
    context: Optional[dict] = Field(None, description="Context for enrichment")


class ProcessEvidenceRequest(BaseModel):
    """Request for evidence processing"""
    raw_evidence: str = Field(..., description="Raw evidence")
    evidence_type: str = Field(default="http_response", description="Evidence type")


# Initialize modules
log_cleaner = LogCleaner()
context_reducer = ContextReducer()
evidence_processor = EvidenceProcessor()
finding_enricher = FindingEnricher()


@router.post("/clean-log")
async def clean_log(request: CleanLogRequest):
    """Clean raw scanner output"""
    cleaned = log_cleaner.clean_log(request.raw_log)
    findings = log_cleaner.extract_findings(request.raw_log)
    stats = log_cleaner.get_log_statistics(request.raw_log)

    return {
        "cleaned_log": cleaned,
        "extracted_findings": findings,
        "statistics": stats
    }


@router.post("/categorize")
async def categorize_findings(request: CleanLogRequest):
    """Categorize findings from log"""
    findings = log_cleaner.extract_findings(request.raw_log)
    categorized = log_cleaner.categorize_findings(findings, request.log_type)

    return {
        "categories": categorized,
        "total_findings": len(findings),
        "vulnerabilities": len(categorized.get("vulnerabilities", [])),
        "endpoints": len(categorized.get("endpoints", []))
    }


@router.post("/reduce-context")
async def reduce_context(request: dict):
    """Reduce context for AI consumption"""
    findings = request.get("findings", [])
    context = request.get("context")

    reduced = context_reducer.reduce_for_ai(findings, context)

    return {
        "reduced_context": reduced
    }


@router.post("/process-evidence")
async def process_evidence(request: ProcessEvidenceRequest):
    """Process raw evidence"""
    processed = evidence_processor.process_evidence(
        request.raw_evidence,
        request.evidence_type
    )

    return processed


@router.post("/enrich-finding")
async def enrich_finding(request: EnrichRequest):
    """Enrich finding with additional data"""
    enriched = finding_enricher.enrich_finding(
        request.finding,
        request.context
    )

    return enriched


@router.post("/enrich-batch")
async def enrich_batch(request: dict):
    """Enrich multiple findings"""
    findings = request.get("findings", [])
    context = request.get("context")

    enriched = finding_enricher.enrich_batch(findings, context)

    return {
        "enriched_findings": enriched,
        "total": len(enriched)
    }


@router.post("/summarize")
async def summarize_findings(request: dict):
    """Generate summary for findings"""
    findings = request.get("findings", [])
    summary = finding_enricher.generate_finding_summary(findings)

    return {
        "summary": summary
    }


@router.post("/risk-matrix")
async def calculate_risk_matrix(request: dict):
    """Calculate risk matrix for findings"""
    findings = request.get("findings", [])
    risk_matrix = finding_enricher.calculate_risk_matrix(findings)

    return risk_matrix


@router.post("/generate-report")
async def generate_report(request: dict):
    """Generate comprehensive finding report"""
    target_id = request.get("target_id")
    scan_id = request.get("scan_id")
    findings = request.get("findings", [])

    if not target_id or not scan_id or not findings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required fields: target_id, scan_id, findings"
        )

    report = finding_enricher.generate_finding_report(
        target_id,
        findings,
        scan_id
    )

    return {
        "report": report,
        "format": "markdown",
        "target_id": target_id,
        "scan_id": scan_id
    }