#!/usr/bin/env bash
# prepara los secretos locales, completa la pki y arranca docker compose (uso: scripts/start.sh, los argumentos se pasan a gen_certs.py, por ejemplo --san 54.1.2.3)
set -euo pipefail
cd "$(dirname "$0")/.."

prepare_args=(--docker-checked)
if [ ! -f .env ]; then
  project="${COMPOSE_PROJECT_NAME:-$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-' | sed 's/^[-_]*//')}"
  if [ -z "$project" ]; then
    echo "Define COMPOSE_PROJECT_NAME para identificar los volúmenes Docker." >&2
    exit 1
  fi
  volumes="$(docker volume ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}')"
  if [ -n "$volumes" ]; then
    prepare_args+=(--existing-data)
  fi
fi

if python3 -c "import cryptography" 2>/dev/null; then
  python3 scripts/prepare_local.py "${prepare_args[@]}"
  python3 scripts/gen_certs.py "$@"
else
  # los argumentos son parámetros de sh, nunca parte del programa que se ejecuta
  docker run --rm --user "$(id -u):$(id -g)" -e CLUSTER_SECRET -v "$PWD":/w -w /w python:3.11-slim \
    python scripts/prepare_local.py "${prepare_args[@]}"
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/w -w /w python:3.11-slim \
    sh -c 'pip install -q --target /tmp/dfsha-python cryptography && PYTHONPATH=/tmp/dfsha-python python scripts/gen_certs.py "$@"' sh "$@"
fi
exec docker compose up --build -d
