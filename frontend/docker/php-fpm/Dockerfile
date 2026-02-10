# syntax=docker/dockerfile:1.7

# ------------------------------------------------------------
# Notes / How to build:
#   - Ensure BuildKit is enabled for cache mounts:
#       export DOCKER_BUILDKIT=1
#       export COMPOSE_DOCKER_CLI_BUILD=1
#       docker compose build frontend_php_fpm
#
#   - Optional: provide a GitHub token to reduce 429s (BuildKit secret):
#       Create: ./secrets/composer-auth.json
#       {
#         "github-oauth": { "github.com": "YOUR_TOKEN" }
#       }
# ------------------------------------------------------------

# ------------------------------------------------------------
# Stage 1a: vendor install for PROD (no-dev) with proper caching
# ------------------------------------------------------------
FROM composer:2 AS vendor_prod
WORKDIR /app

# Copy ONLY dependency manifests first (this makes the layer reusable)
COPY composer.json composer.lock ./
# symfony.lock is optional; copy it only if you have it in repo
# (If you do have it, keep this line. If you don't, remove it.)
COPY symfony.lock* ./

RUN --mount=type=cache,target=/tmp/composer-cache \
    --mount=type=secret,id=composer_auth,required=false,target=/root/.composer/auth.json \
    set -eux; \
    export COMPOSER_CACHE_DIR=/tmp/composer-cache; \
    COMPOSER_ALLOW_SUPERUSER=1 composer install \
      --no-dev --prefer-dist --no-interaction --no-progress \
      --no-scripts --no-autoloader

# Now copy the rest of the app (changes here won't force re-downloads)
COPY . /app

RUN --mount=type=cache,target=/tmp/composer-cache \
    set -eux; \
    export COMPOSER_CACHE_DIR=/tmp/composer-cache; \
    composer dump-autoload --no-dev --classmap-authoritative


# ------------------------------------------------------------
# Stage 1b: vendor install for DEV (with require-dev) with proper caching
# ------------------------------------------------------------
FROM composer:2 AS vendor_dev
WORKDIR /app

COPY composer.json composer.lock ./
COPY symfony.lock* ./

RUN --mount=type=cache,target=/tmp/composer-cache \
    --mount=type=secret,id=composer_auth,required=false,target=/root/.composer/auth.json \
    set -eux; \
    export COMPOSER_CACHE_DIR=/tmp/composer-cache; \
    COMPOSER_ALLOW_SUPERUSER=1 composer install \
      --prefer-dist --no-interaction --no-progress \
      --no-scripts --no-autoloader

COPY . /app

RUN --mount=type=cache,target=/tmp/composer-cache \
    set -eux; \
    export COMPOSER_CACHE_DIR=/tmp/composer-cache; \
    composer dump-autoload --optimize


# ------------------------------------------------------------
# Stage 2: runtime base (extensions + your config/entrypoint)
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
