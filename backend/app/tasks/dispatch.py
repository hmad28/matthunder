from app.config import settings


def celery_enabled() -> bool:
    """Return true when an external broker is configured."""
    return bool(settings.CELERY_BROKER_URL or settings.REDIS_URL)

