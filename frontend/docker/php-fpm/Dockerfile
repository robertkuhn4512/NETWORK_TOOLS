FROM composer:2 AS vendor

WORKDIR /app

# Copy whatever is in ./frontend into the build context.
# If ./frontend does NOT yet contain a Symfony project (no composer.json),
# we will scaffold Symfony below.
COPY . /app

RUN set -eux; \
    need_scaffold=0; \
    if [ ! -f /app/composer.json ]; then \
      need_scaffold=1; \
    else \
      # Treat an empty or invalid composer.json as "missing" (common when pre-populating folder structure) \
      php -r '$p="/app/composer.json"; $j=@file_get_contents($p); if($j===false){exit(1);} json_decode($j,true); exit(json_last_error()===JSON_ERROR_NONE ? 0 : 1);' \
        || need_scaffold=1; \
    fi; \
    if [ "${need_scaffold}" -eq 1 ]; then \
      echo "composer.json missing/invalid; scaffolding Symfony full stack (website-skeleton)"; \
      # Keep any infra/ops assets you already placed in ./frontend (docker/, vault_agent/, etc.)
      mkdir -p /tmp/overlay; \
      if [ -d /app/docker ]; then cp -a /app/docker /tmp/overlay/; fi; \
      if [ -d /app/vault_agent ]; then cp -a /app/vault_agent /tmp/overlay/; fi; \
      if [ -d /app/bin ]; then cp -a /app/bin /tmp/overlay/; fi; \
      \
      # Create Symfony project in an empty directory (create-project fails if target isn't empty)
      composer create-project symfony/website-skeleton:"8.0.*" /tmp/symfony --no-interaction --no-progress; \
      cd /tmp/symfony; \
      \
      # You said you don't need Doctrine; website-skeleton typically includes it.
      # Remove it if present (no-op if it's not installed).
            composer remove symfony/orm-pack doctrine/doctrine-bundle doctrine/orm doctrine/doctrine-migrations-bundle --no-interaction --no-progress || true; \
      # If recipes left doctrine config files behind, remove them to avoid runtime config load errors \
      rm -f config/packages/doctrine*.yaml config/routes/doctrine*.yaml || true; \

      \
      # Ensure HTTP client for Symfony -> Keycloak token calls and Symfony -> FastAPI requests.
      composer require symfony/http-client --no-interaction --no-progress; \
      \
      # Replace /app contents with the scaffold, then restore overlay dirs
      find /app -mindepth 1 -maxdepth 1 -exec rm -rf {} +; \
      cp -a /tmp/symfony/. /app/; \
      if [ -d /tmp/overlay/docker ]; then cp -a /tmp/overlay/docker /app/; fi; \
      if [ -d /tmp/overlay/vault_agent ]; then cp -a /tmp/overlay/vault_agent /app/; fi; \
      if [ -d /tmp/overlay/bin ]; then cp -a /tmp/overlay/bin /app/; fi; \
    fi; \
    \
    # Install prod deps.
    # NOTE: we skip composer scripts during image build because your real env is injected by Vault
    # at runtime (APP_SECRET, Keycloak config, etc.). You can run cache warmup after env is loaded.
    COMPOSER_ALLOW_SUPERUSER=1 composer install \
      --no-dev --prefer-dist --no-interaction --no-progress --optimize-autoloader --no-scripts; \
    composer dump-autoload --no-dev --classmap-authoritative


FROM php:8.5-fpm-alpine

# system deps + php extensions
RUN set -eux; \
    apk add --no-cache \
      bash icu-dev libzip-dev postgresql-dev oniguruma-dev; \
    docker-php-ext-install -j"$(nproc)" intl pdo pdo_pgsql zip; \
    rm -rf /tmp/*

WORKDIR /var/www/html

# Copy application + vendor
COPY --from=vendor /app /var/www/html

# php.ini + fpm pool overrides + entrypoint
# php.ini + fpm pool overrides + entrypoint
COPY docker/php-fpm/php.ini /usr/local/etc/php/conf.d/zz-networktools.ini
COPY docker/php-fpm/zz-www.conf /usr/local/etc/php-fpm.d/zz-networktools.conf
COPY docker/php-fpm/entrypoint_from_vault.sh /usr/local/bin/entrypoint_from_vault.sh
RUN chmod +x /usr/local/bin/entrypoint_from_vault.sh

EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/entrypoint_from_vault.sh"]
CMD ["php-fpm", "-F"]
