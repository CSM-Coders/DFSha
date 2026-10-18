#!/usr/bin/env bash
# prepara una vm (amazon linux 2023 o ubuntu) para correr dfsha: instala docker, compose y git, se usa como user data de la instancia ec2 o se ejecuta una vez por ssh
set -euo pipefail

if command -v dnf >/dev/null; then
  sudo dnf install -y docker git
elif command -v apt-get >/dev/null; then
  sudo apt-get update && sudo apt-get install -y docker.io git curl
fi
sudo systemctl enable --now docker
sudo usermod -aG docker "${SUDO_USER:-${USER:-ec2-user}}" || true

if ! docker compose version >/dev/null 2>&1; then
  sudo mkdir -p /usr/local/lib/docker/cli-plugins
  sudo curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" \
       -o /usr/local/lib/docker/cli-plugins/docker-compose
  sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi
# docker compose build pide buildx 0.17 o más y amazon linux 2023 trae la 0.12, así que se instala una versión reciente
BUILDX_VERSION=v0.19.3
case "$(uname -m)" in x86_64) BARCH=amd64 ;; aarch64) BARCH=arm64 ;; *) BARCH=amd64 ;; esac
if ! docker buildx version 2>/dev/null | grep -qE 'buildx v?0\.(1[7-9]|[2-9][0-9])|buildx v?[1-9]'; then
  sudo mkdir -p /usr/local/lib/docker/cli-plugins
  sudo curl -fsSL "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-${BARCH}" \
       -o /usr/local/lib/docker/cli-plugins/docker-buildx
  sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
fi
docker compose version
docker buildx version
echo "Listo. Cierra sesión y vuelve a entrar para usar docker sin sudo."
