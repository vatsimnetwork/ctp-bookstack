# syntax=docker/dockerfile:1
# Production image for ctp-bookstack.
# Build context: ./ctp-bookstack (this directory).

# Stage 1: build frontend assets
FROM node:22-alpine AS node-builder

WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run production

# Stage 2: install PHP/Composer dependencies
FROM composer:2 AS composer-builder

WORKDIR /src
COPY . .
RUN mkdir -p bootstrap/cache storage/framework/{views,cache,sessions} storage/logs && \
    composer install --no-dev --no-interaction --optimize-autoloader --ignore-platform-reqs

# Stage 3: final image using the linuxserver base
FROM ghcr.io/linuxserver/baseimage-alpine-nginx:3.23

ARG BUILD_DATE
ARG VERSION
LABEL build_version="CTP BookStack version:- ${VERSION} Build-date:- ${BUILD_DATE}"
LABEL maintainer="ctp"

ENV S6_STAGE2_HOOK="/init-hook"

RUN \
  echo "**** install runtime packages ****" && \
  apk add --no-cache \
    fontconfig \
    mariadb-client \
    memcached \
    php85-dom \
    php85-exif \
    php85-gd \
    php85-ldap \
    php85-mysqlnd \
    php85-pdo_mysql \
    php85-pecl-memcached \
    php85-tokenizer \
    qt5-qtbase \
    ttf-freefont && \
  echo "**** configure php-fpm to pass env vars ****" && \
  sed -E -i 's/^;?clear_env ?=.*$/clear_env = no/g' /etc/php85/php-fpm.d/www.conf && \
  if ! grep -qxF 'clear_env = no' /etc/php85/php-fpm.d/www.conf; then echo 'clear_env = no' >> /etc/php85/php-fpm.d/www.conf; fi && \
  echo "env[PATH] = /usr/local/bin:/usr/bin:/bin" >> /etc/php85/php-fpm.conf && \
  mkdir -p /app/www

# Copy app source (PHP + vendor) and built frontend assets
COPY --from=composer-builder /src /app/www/
COPY --from=node-builder /src/public/dist /app/www/public/dist/

RUN \
  echo "**** create symlinks ****" && \
  /bin/bash -c \
  'dst=(www/themes www/files www/images www/uploads backups www/framework/cache www/framework/sessions www/framework/views www/framework/purifier log/bookstack/laravel.log www/.env); \
  src=(themes storage/uploads/files storage/uploads/images public/uploads storage/backups storage/framework/cache storage/framework/sessions storage/framework/views storage/framework/purifier storage/logs/laravel.log .env); \
  for i in "${!src[@]}"; do rm -rf /app/www/"${src[i]}" && ln -s /config/"${dst[i]}" /app/www/"${src[i]}"; done' && \
  echo "**** cleanup ****" && \
  rm -rf \
    /tmp/* \
    $HOME/.cache

# Copy s6-overlay service definitions and init scripts
COPY docker/ /

EXPOSE 80 443
VOLUME /config
