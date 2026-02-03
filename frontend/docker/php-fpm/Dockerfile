# ------------------------------------------------------------
# Stage 1: build a consistent /app tree (and scaffold if missing)
# ------------------------------------------------------------
FROM composer:2 AS scaffold
WORKDIR /app

# Copy whatever is in ./frontend into the build context.
COPY . /app

RUN set -eux; \
    need_scaffold=0; \
    if [ ! -f /app/composer.json ]; then \
      need_scaffold=1; \
    else \
      php -r '$p="/app/composer.json"; $j=@file_get_contents($p); if($j===false){exit(1);} json_decode($j,true); exit(json_last_error()===JSON_ERROR_NONE ? 0 : 1);' \
        || need_scaffold=1; \
    fi; \
    if [ "${need_scaffold}" -eq 1 ]; then \
      echo "composer.json missing/invalid; scaffolding Symfony full stack (website-skeleton)"; \
      mkdir -p /tmp/overlay; \
      if [ -d /app/docker ]; then cp -a /app/docker /tmp/overlay/; fi; \
      if [ -d /app/vault_agent ]; then cp -a /app/vault_agent /tmp/overlay/; fi; \
      if [ -d /app/bin ]; then cp -a /app/bin /tmp/overlay/; fi; \
      composer create-project symfony/website-skeleton:"8.0.*" /tmp/symfony --no-interaction --no-progress; \
      cd /tmp/symfony; \
      composer remove symfony/orm-pack doctrine/doctrine-bundle doctrine/orm doctrine/doctrine-migrations-bundle --no-interaction --no-progress || true; \
      rm -f config/packages/doctrine*.yaml config/routes/doctrine*.yaml || true; \
      composer require symfony/http-client --no-interaction --no-progress; \
      find /app -mindepth 1 -maxdepth 1 -exec rm -rf {} +; \
      cp -a /tmp/symfony/. /app/; \
      if [ -d /tmp/overlay/docker ]; then cp -a /tmp/overlay/docker /app/; fi; \
      if [ -d /tmp/overlay/vault_agent ]; then cp -a /tmp/overlay/vault_agent /app/; fi; \
      if [ -d /tmp/overlay/bin ]; then cp -a /tmp/overlay/bin /app/; fi; \
    fi

# ------------------------------------------------------------
# Stage 2a: vendor install for PROD (no-dev)
# ------------------------------------------------------------
FROM scaffold AS vendor_prod
RUN set -eux; \
    COMPOSER_ALLOW_SUPERUSER=1 composer install \
      --no-dev --prefer-dist --no-interaction --no-progress \
      --optimize-autoloader --no-scripts; \
    composer dump-autoload --no-dev --classmap-authoritative

# ------------------------------------------------------------
# Stage 2b: vendor install for DEV (with require-dev)
# ------------------------------------------------------------
FROM scaffold AS vendor_dev
RUN set -eux; \
    COMPOSER_ALLOW_SUPERUSER=1 composer install \
      --prefer-dist --no-interaction --no-progress \
      --optimize-autoloader --no-scripts; \
    composer dump-autoload --optimize

# ------------------------------------------------------------
# Stage 3: runtime base (extensions + your config/entrypoint)
# ------------------------------------------------------------
FROM php:8.5-fpm-alpine AS runtime_base

RUN set -eux; \
    apk add --no-cache bash icu-dev libzip-dev postgresql-dev oniguruma-dev; \
    docker-php-ext-install -j"$(nproc)" intl pdo pdo_pgsql zip; \
    rm -rf /tmp/*

WORKDIR /var/www/html

COPY docker/php-fpm/php.ini /usr/local/etc/php/conf.d/zz-networktools.ini
COPY docker/php-fpm/zz-www.conf /usr/local/etc/php-fpm.d/zz-networktools.conf
COPY docker/php-fpm/entrypoint_from_vault.sh /usr/local/bin/entrypoint_from_vault.sh
RUN chmod +x /usr/local/bin/entrypoint_from_vault.sh

EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/entrypoint_from_vault.sh"]
CMD ["php-fpm", "-F"]

# ------------------------------------------------------------
# Target: PROD
# ------------------------------------------------------------
FROM runtime_base AS prod
COPY --from=vendor_prod /app /var/www/html
ENV APP_ENV=prod \
    APP_DEBUG=0

# ------------------------------------------------------------
# Target: DEV
# ------------------------------------------------------------
FROM runtime_base AS dev
COPY --from=vendor_dev /app /var/www/html
ENV APP_ENV=dev \
    APP_DEBUG=1
