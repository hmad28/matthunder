"""
API v1 router aggregation
"""
from fastapi import APIRouter
from app.api.v1 import auth, targets, scans, findings, scanners, pipeline, ai, config, acunetix, reports

router = APIRouter(prefix="/api/v1")

router.include_router(auth.router)
router.include_router(targets.router)
router.include_router(scans.router)
router.include_router(findings.router)
router.include_router(scanners.router)
router.include_router(pipeline.router)
router.include_router(ai.router)
router.include_router(config.router)
router.include_router(acunetix.router)
router.include_router(reports.router)
