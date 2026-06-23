"""
API v1 router aggregation
"""
from fastapi import APIRouter
from app.api.v1 import public, targets, scans, findings, scanners, pipeline, ai, config, acunetix, reports, approvals, audit, reasoning, generation, parsing, swarm, ouroboros, memory

router = APIRouter(prefix="/api/v1")

router.include_router(public.router)
router.include_router(targets.router)
router.include_router(scans.router)
router.include_router(findings.router)
router.include_router(scanners.router)
router.include_router(pipeline.router)
router.include_router(ai.router)
router.include_router(config.router)
router.include_router(acunetix.router)
router.include_router(reports.router)
router.include_router(approvals.router)
router.include_router(audit.router)
router.include_router(reasoning.router)
router.include_router(generation.router)
router.include_router(parsing.router)
router.include_router(swarm.router)
router.include_router(ouroboros.router)
router.include_router(memory.router)
