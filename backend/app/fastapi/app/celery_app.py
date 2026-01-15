# /app/app/celery_app.py  (repo: backend/app/fastapi/app/celery_app.py)

import os
from celery import Celery

def _env(name: str, default: str = "") -> str:
    v = os.getenv(name, default)
    return v.strip() if isinstance(v, str) else default

def _redis_url(db: str) -> str:
    host = _env("REDIS_HOST", "redis")
    port = _env("REDIS_PORT", "6379")
    password = _env("REDIS_PASSWORD", "")
    auth = f":{password}@" if password else ""
    return f"redis://{auth}{host}:{port}/{db}"

BROKER_URL = _env("CELERY_BROKER_URL") or _redis_url(_env("CELERY_BROKER_DB", "0"))
RESULT_BACKEND = _env("CELERY_RESULT_BACKEND") or _redis_url(_env("CELERY_RESULT_DB", "1"))

celery_app = Celery(
    "network_tools",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=[
        "app.tasks"
    ],
)

celery_app.conf.update(
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    task_track_started=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
)
