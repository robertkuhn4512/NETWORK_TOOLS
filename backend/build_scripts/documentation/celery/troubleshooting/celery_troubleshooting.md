docker exec -it celery_worker python /app/vault_env_exec.py \
  celery -A app.celery_app:celery_app inspect active

docker exec -it celery_worker python /app/vault_env_exec.py \
  celery -A app.celery_app:celery_app inspect reserved

docker exec -it celery_worker python /app/vault_env_exec.py \
  celery -A app.celery_app:celery_app inspect scheduled

docker exec -it celery_worker python /app/vault_env_exec.py \
  celery -A app.celery_app:celery_app inspect registered


## Clear any qued jobs

docker exec -it celery_worker python /app/vault_env_exec.py \
  celery -A app.celery_app:celery_app purge -f