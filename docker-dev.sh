#!/bin/bash
# Development Docker script for SecretHub
# Sets up and runs complete development environment

set -e

echo "🐳 SecretHub Docker Development Environment Setup"
echo "=============================================="

# Function to check if service is healthy
check_service_health() {
    local service=$1
    echo "Checking $service health..."
    for i in {1..30}; do
        if docker compose ps "$service" | grep -q "healthy"; then
            echo "✅ $service is healthy"
            return 0
        fi
        echo "⏳ Waiting for $service... ($i/30)"
        sleep 2
    done
    echo "❌ $service failed to become healthy"
    return 1
}

# Function to show logs
show_logs() {
    local service=$1
    echo "📋 Showing logs for $service (Ctrl+C to exit):"
    docker compose logs -f "$service"
}

# Build and start services
echo "🏗 Building Docker images..."
docker compose build

echo "🚀 Starting development environment..."
docker compose up -d

# Wait for services to be healthy
echo "🏥 Checking service health..."
check_service_health "postgres" || {
    echo "❌ PostgreSQL failed to start"
    docker compose down
    exit 1
}

check_service_health "redis" || {
    echo "❌ Redis failed to start"
    docker compose down
    exit 1
}

check_service_health "secrethub-core" || {
    echo "❌ SecretHub Core failed to start"
    show_logs "secrethub-core"
    exit 1
}

echo "✅ All services are healthy!"
echo ""
echo "🌐 Services available at:"
echo "  • SecretHub Core: http://localhost:4000"
echo "  • Health Check: http://localhost:4000/health"
echo "  • PostgreSQL: localhost:5432"
echo "  • Redis: localhost:6379"
echo ""
echo "📋 Useful commands:"
echo "  • View logs:     docker compose logs -f [service-name]"
echo "  • Stop services:  docker compose down"
echo "  • Restart:        docker compose restart [service-name]"
echo "  • Shell into Core: docker exec -it secrethub-core bash"
echo "  • Shell into Agent: docker exec -it secrethub-agent bash"
echo ""
echo "🎯 Development environment ready!"