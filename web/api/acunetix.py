"""
web/api/acunetix.py — Acunetix integration endpoints.

Uses the real scanners/acunetix.py module functions.
"""

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/acunetix", tags=["acunetix"])


def _load():
    try:
        import scanners.acunetix as acx
        return acx
    except ImportError:
        raise HTTPException(status_code=501, detail="Acunetix module not available")


def _get_client():
    acx = _load()
    try:
        cfg = acx._load_config()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Acunetix config error: {e}")
    return acx._client(cfg), acx, cfg


@router.get("/status")
async def acx_status():
    """Check Acunetix connectivity."""
    try:
        client, acx, cfg = _get_client()
        info = acx._get(client, "info")
        return {
            "connected": True,
            "url": cfg.get("url", ""),
            "info": info,
        }
    except HTTPException:
        raise
    except Exception as e:
        return {"connected": False, "error": str(e)}


@router.get("/targets")
async def acx_targets():
    """List Acunetix targets."""
    try:
        client, acx, _ = _get_client()
        targets = acx.fetch_targets(client)
        return {"targets": targets}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans")
async def acx_scans():
    """List Acunetix scans."""
    try:
        client, acx, _ = _get_client()
        scans = acx.fetch_scans(client)
        return {"scans": scans}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulns/{scan_id}")
async def acx_vulns_by_scan(scan_id: str):
    """List vulnerabilities for a specific scan."""
    try:
        client, acx, _ = _get_client()
        vulns = acx.fetch_vulnerabilities(client, scan_id)
        return {"vulnerabilities": vulns}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vuln-detail/{vuln_id}")
async def acx_vuln_detail(vuln_id: str):
    """Get full detail of a specific vulnerability."""
    try:
        client, acx, _ = _get_client()
        detail = acx.fetch_vuln_detail(client, vuln_id)
        return {"vulnerability": detail}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/profiles")
async def acx_profiles():
    """List Acunetix scan profiles."""
    try:
        client, acx, _ = _get_client()
        profiles = acx.fetch_profiles(client)
        return {"profiles": profiles}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/start-scan")
async def acx_start_scan(body: dict):
    """Start an Acunetix scan on a target."""
    target_id = body.get("target_id")
    profile_id = body.get("profile_id")
    if not target_id:
        raise HTTPException(status_code=400, detail="target_id required")
    try:
        client, acx, _ = _get_client()
        result = acx.start_scan(client, target_id, profile_id)
        return {"result": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
