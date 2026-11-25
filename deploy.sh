#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEPLOY_DIR"

echo "=== Deploying VisionX Auth Service ==="
echo "Working directory: $DEPLOY_DIR"

git fetch origin main
git reset --hard origin/main

docker compose down --remove-orphans || true
docker compose up -d --build --remove-orphans

echo "Waiting for auth service to become healthy..."
docker compose ps
