#!/usr/bin/env bash
# Argus first-run setup script
set -euo pipefail

echo "🦅 Argus — first-run setup"

# 1. Copy env file if not present
if [ ! -f .env ]; then
  cp .env.example .env
  echo "✅  Created .env from .env.example — please review and edit before starting."
else
  echo "ℹ️   .env already exists, skipping."
fi

# 2. Pull and build containers
docker compose build

# 3. Start DB and Redis first
docker compose up -d db redis

# 4. Wait for DB to be healthy
echo "⏳  Waiting for Postgres..."
until docker compose exec db pg_isready -U argus; do sleep 2; done
echo "✅  Postgres ready."

# 5. Start remaining services
docker compose up -d

echo ""
echo "🚀  Argus is running!"
echo "   Frontend: http://localhost:3000"
echo "   API:      http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
