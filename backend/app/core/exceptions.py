"""
Custom exceptions for matthunder backend
"""
from fastapi import HTTPException, status


class NotFoundException(HTTPException):
    """Resource not found"""
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class BadRequestException(HTTPException):
    """Bad request"""
    def __init__(self, detail: str = "Bad request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class UnauthorizedException(HTTPException):
    """Unauthorized"""
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"}
        )


class ForbiddenException(HTTPException):
    """Forbidden"""
    def __init__(self, detail: str = "Forbidden"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class ConflictException(HTTPException):
    """Conflict"""
    def __init__(self, detail: str = "Conflict"):
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail)


class ScanException(HTTPException):
    """Scan-related error"""
    def __init__(self, detail: str = "Scan error"):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail)


class ScannerNotFoundException(NotFoundException):
    """Scanner not found"""
    def __init__(self, scanner_name: str):
        super().__init__(detail=f"Scanner '{scanner_name}' not found")


class TargetNotFoundException(NotFoundException):
    """Target not found"""
    def __init__(self, target_id: str):
        super().__init__(detail=f"Target '{target_id}' not found")


class ScanNotFoundException(NotFoundException):
    """Scan not found"""
    def __init__(self, scan_id: str):
        super().__init__(detail=f"Scan '{scan_id}' not found")


class FindingNotFoundException(NotFoundException):
    """Finding not found"""
    def __init__(self, finding_id: str):
        super().__init__(detail=f"Finding '{finding_id}' not found")
