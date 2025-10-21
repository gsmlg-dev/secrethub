# Multi-stage Dockerfile for SecretHub Agent
# Lightweight daemon for deployment alongside applications

# =====================================
# Build Stage
# =====================================
FROM elixir:1.18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    git

# Set working directory
WORKDIR /app

# Copy mix files
COPY mix.exs mix.lock ./
COPY config config/

# Copy shared library
COPY ../secrethub_shared secrethub_shared/

# Install Elixir dependencies
RUN mix local.hex --force && \
    mix local.rebar --force && \
    mix deps.get --only $MIX_ENV

# Copy application code
COPY lib lib/

# Build OTP release
RUN mix release --overwrite

# =====================================
# Runtime Stage
# =====================================
FROM alpine:3.19 AS runtime

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    ca-certificates \
    curl \
    socat \
    && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g secrethub secrethub && \
    adduser -D -u 1002 -G secrethub secrethub

# Create application directory
WORKDIR /app

# Copy built OTP release from builder stage
COPY --from=builder --chown=secrethub:secrethub /app/_build .

# Set environment variables
ENV AGENT_ID=${AGENT_ID:-agent-default}
ENV CORE_URL=${CORE_URL:-ws://localhost:4000}
ENV MIX_ENV=prod

# Create necessary directories for agent operation
RUN mkdir -p /app/var/log && \
    mkdir -p /app/tmp && \
    mkdir -p /app/etc/certs && \
    chown -R secrethub:secrethub /app/var /app/tmp /app/etc

# Switch to non-root user
USER secrethub

# Health check for the agent
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD test -S /app/var/log || exit 1

# Entrypoint
ENTRYPOINT ["bin/secrethub_agent"]

# Labels for orchestration
LABEL maintainer="SecretHub Development Team" \
      version="0.1.0" \
      description="SecretHub Agent - Daemon for secure secret delivery to applications" \
      org.opencontainers.image.source="https://github.com/secrethub/secrethub" \
      org.opencontainers.image.licenses="MIT"

# Default command to run if no arguments provided
CMD ["start"]