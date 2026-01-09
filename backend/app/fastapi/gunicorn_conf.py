"""
gunicorn_conf.py

Notes / How to run
- Used by run_server.py to start Gunicorn with:
    gunicorn -c /app/gunicorn_conf.py <app_module>
- Configuration is driven by environment variables set in docker-compose.

Key env vars
- BIND_HOST (default: 0.0.0.0)
- BIND_PORT (default: 8000)
- WEB_CONCURRENCY (default: 2)
- GUNICORN_TIMEOUT (default: 60)
"""
import os

bind_host = os.getenv("BIND_HOST", "0.0.0.0")
bind_port = os.getenv("BIND_PORT", "8000")
bind = f"{bind_host}:{bind_port}"

workers = int(os.getenv("WEB_CONCURRENCY", "2"))

# Uvicorn worker (recommended over deprecated uvicorn.workers)
worker_class = "uvicorn_worker.UvicornWorker"

timeout = int(os.getenv("GUNICORN_TIMEOUT", "60"))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))

# Log to stdout/stderr (container-friendly)
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")

# Optional: mitigate slow memory growth by recycling workers
# (Enable later if needed)
max_requests = int(os.getenv("GUNICORN_MAX_REQUESTS", "0"))  # 0 disables
max_requests_jitter = int(os.getenv("GUNICORN_MAX_REQUESTS_JITTER", "0"))
