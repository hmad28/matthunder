"""
Celery application configuration
"""
from celery import Celery
from app.config import settings

broker_url = settings.CELERY_BROKER_URL or settings.REDIS_URL or "memory://"
result_backend = settings.CELERY_RESULT_BACKEND or settings.REDIS_URL or "cache+memory://"

celery = Celery(
    "matthunder",
    broker=broker_url,
    backend=result_backend
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour
    task_soft_time_limit=3500,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
)

# Auto-discover tasks
celery.autodiscover_tasks(["app.tasks"])
