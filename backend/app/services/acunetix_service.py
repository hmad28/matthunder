"""
Acunetix Service - Integration with Acunetix API
"""
import httpx
from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class AcunetixService:
    """Service for Acunetix integration"""
    
    @staticmethod
    async def _get_client() -> httpx.AsyncClient:
        """Get HTTP client with Acunetix auth"""
        return httpx.AsyncClient(
            base_url=settings.ACUNETIX_URL,
            headers={
                "X-Auth": settings.ACUNETIX_API_KEY,
                "Content-Type": "application/json"
            },
            verify=settings.ACUNETIX_VERIFY_SSL,
            timeout=30.0
        )
    
    @staticmethod
    async def check_connection() -> dict:
        """Check Acunetix connection"""
        try:
            async with await AcunetixService._get_client() as client:
                response = await client.get("/api/v1/info")
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "connected": True,
                        "version": data.get("version"),
                        "message": "Connected successfully"
                    }
                else:
                    return {
                        "connected": False,
                        "message": f"HTTP {response.status_code}"
                    }
        except Exception as e:
            logger.error("acunetix_connection_failed", error=str(e))
            return {
                "connected": False,
                "message": str(e)
            }
    
    @staticmethod
    async def get_targets() -> list[dict]:
        """Get targets from Acunetix"""
        async with await AcunetixService._get_client() as client:
            response = await client.get("/api/v1/targets")
            response.raise_for_status()
            data = response.json()
            return data.get("targets", [])
    
    @staticmethod
    async def get_scans(limit: int = 50) -> list[dict]:
        """Get scans from Acunetix"""
        async with await AcunetixService._get_client() as client:
            response = await client.get(f"/api/v1/scans?limit={limit}")
            response.raise_for_status()
            data = response.json()
            return data.get("scans", [])
    
    @staticmethod
    async def get_vulnerabilities(limit: int = 100) -> list[dict]:
        """Get vulnerabilities from Acunetix"""
        async with await AcunetixService._get_client() as client:
            response = await client.get(f"/api/v1/vulnerabilities?limit={limit}")
            response.raise_for_status()
            data = response.json()
            return data.get("vulnerabilities", [])
    
    @staticmethod
    async def get_scan_vulnerabilities(scan_id: str) -> list[dict]:
        """Get vulnerabilities for a specific scan"""
        async with await AcunetixService._get_client() as client:
            response = await client.get(f"/api/v1/scans/{scan_id}/vulnerabilities")
            response.raise_for_status()
            data = response.json()
            return data.get("vulnerabilities", [])
