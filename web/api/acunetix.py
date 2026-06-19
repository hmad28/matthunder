"""
web/api/acunetix.py — Acunetix integration endpoints.

Proxies to scanners/acunetix.py so the web frontend can
list targets, scans, and vulnerabilities from Acunetix.
"""

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/acunetix", tags=["acunetix"])

# Lazy import to avoid crashing if acunetix module is unavailable


def _get_acx():
    try:
        import scanners.acunetix as acx
        return acx
    except ImportError:
        raise HTTPException(status_code=501, detail="Acunetix module not available")


def _client(cfg=None):
    acx = _get_acx()
    if cfg is None:
        try:
            cfg = acx._load_cfg()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    return acx._client(cfg)


def _get(client, path):
    return _get_acx()._get(client, path)


@router.get("/status")
async def acx_status():
    """Check Acunetix connectivity and return basic info."""
    try:
        acx = _get_acx()
        cfg = acx._load_cfg()
        with acx._client(cfg) as c:
            info = acx._get(c, "info")
        return {
            "connected": True,
            "url": cfg.get("url", ""),
            "info": info,
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}


@router.get("/targets")
async def acx_targets():
    """List Acunetix targets."""
    try:
        acx = _get_acx()
        cfg = acx._load_cfg()
        with acx._client(cfg) as c:
            data = acx._get(c, "targets")
        targets = data.get("targets", []) if isinstance(data, dict) else []
        return {"targets": targets}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans")
async def acx_scans(limit: int = 20):
    """List recent Acunetix scans."""
    try:
        acx = _get_acx()
        cfg = acx._load_cfg()
        with acx._client(cfg) as c:
            data = acx._get(c, f"scans?l={limit}")
        scans = data.get("scans", []) if isinstance(data, dict) else []
        return {"scans": scans}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulns")
async def acx_vulns(scan_id: str = None, limit: int = 50):
    """List vulnerabilities, optionally filtered by scan_id."""
    try:
        acx = _get_acx()
        cfg = acx._load_cfg()
        with acx._client(cfg) as c:
            path = f"vulnerabilities?l={limit}"
            if scan_id:
                path += f"&scan_id={scan_id}"
            data = acx._get(c, path)
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        return {"vulnerabilities": vulns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulns/{scan_id}")
async def acx_vulns_by_scan(scan_id: str, limit: int = 100):
    """List vulnerabilities for a specific scan."""
    try:
        acx = _get_acx()
        cfg = acx._load_cfg()
        with acx._client(cfg) as c:
            data = acx._get(c, f"vulnerabilities?l={limit}&scan_id={scan_id}")
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        return {"vulnerabilities": vulns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan-groups")
async def acx_scan_groups():
    """List Acunetix scan groups."""
    try:
        acx = _get_acx()
        cfg = acx._load_cfg()
        with acx._client(cfg) as c:
            data = acx._get(c, "scan_groups")
        groups = data.get("groups", []) if isinstance(data, dict) else []
        return {"groups": groups}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
