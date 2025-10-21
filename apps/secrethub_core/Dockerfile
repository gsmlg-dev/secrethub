# Multi-stage Dockerfile for SecretHub Core Service
# Optimized for production deployment with security best practices

# =====================================
# Build Stage
# =====================================
FROM elixir:1.18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    git \
    nodejs \
    npm

# Set working directory
WORKDIR /app

# Copy mix files
COPY mix.exs mix.lock ./
COPY config config/

# Copy shared library (it's in umbrella)
COPY ../secrethub_shared secrethub_shared/

# Install Elixir dependencies
RUN mix local.hex --force && \
    mix local.rebar --force && \
    mix deps.get --only $MIX_ENV

# Copy application code
COPY lib lib/

# Build OTP release
RUN mix release --overwrite

# Assets compilation (if any were added later)
# COPY ../secrethub_web/assets secrethub_web/assets/
# RUN cd secrethub_web && mix assets.deploy

# =====================================
# Runtime Stage
# =====================================
FROM alpine:3.19 AS runtime

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    ca-certificates \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g secrethub secrethub && \
    adduser -D -u 1001 -G secrethub secrethub

# Create application directory
WORKDIR /app

# Copy built OTP release from builder stage
COPY --from=builder --chown=secrethub:secrethub /app/_build .
# Copy runtime files
COPY --chown=secrethub:secrethub config config/

# Set environment
ENV SECRET_HUB_HOME=/app
ENV PORT=4000
ENV MIX_ENV=prod

# Create necessary directories
RUN mkdir -p /app/var/log && \
    mkdir -p /app/tmp && \
    chown -R secrethub:secrethub /app/var /app/tmp

# Expose port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:4000/health || exit 1

# Switch to non-root user
USER secrethub

# Entrypoint
ENTRYPOINT ["bin/secrethub_core"]

# Labels for orchestration
LABEL maintainer="SecretHub Development Team" \
      version="0.1.0" \
      description="SecretHub Core Service - Enterprise secrets management platform" \
      org.opencontainers.image.source="https://github.com/secrethub/secrethub" \
      org.opencontainers.image.licenses="MIT"