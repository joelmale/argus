#!/usr/bin/env bash
# Argus first-run setup script
set -euo pipefail

compose_files=(-f docker-compose.yml -f docker-compose.dev.yml)

echo "🦅 Argus — first-run setup"

# 1. Copy env file if not present
if [ ! -f .env ]; then
  cp .env.example .env
  echo "✅  Created .env from .env.example — please review and edit before starting."
else
  echo "ℹ️   .env already exists, skipping."
fi

# 2. Build images
docker compose "${compose_files[@]}" build

# 3. Start DB and Redis first
docker compose "${compose_files[@]}" up -d db redis

# 4. Wait for DB and Redis to be healthy
echo "⏳  Waiting for Postgres and Redis..."
until docker compose "${compose_files[@]}" exec db pg_isready -U "${POSTGRES_USER:-argus}" >/dev/null 2>&1; do sleep 2; done
until docker compose "${compose_files[@]}" exec redis redis-cli ping >/dev/null 2>&1; do sleep 2; done
echo "✅  Postgres and Redis ready."

# 5. Start remaining services
docker compose "${compose_files[@]}" up -d

echo ""
echo "🚀  Argus is running!"
echo "   Frontend: http://localhost:3000"
echo "   API:      http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo ""
echo "ℹ️   First frontend startup may take a minute while npm dependencies are installed into the dev volume."
