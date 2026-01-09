# /app/app/tasks.py (repo: backend/app/fastapi/app/tasks.py)

from .celery_app import celery_app

@celery_app.task(bind=True)
def healthcheck_task(self) -> str:
    return "ok"
