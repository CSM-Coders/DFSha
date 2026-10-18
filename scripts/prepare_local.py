#!/usr/bin/env python3
"""Prepara .env sin reemplazar secretos existentes ni perder acceso a datos.

Uso: python scripts/prepare_local.py [--admin]
--admin crea además una contraseña aleatoria de administrador únicamente al
crear .env. Los secretos se guardan en ese archivo; nunca se imprimen.
"""
import argparse
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess


class SetupError(Exception):
    """para preparar el entorno hay que corregir una configuración que ya existe"""


def validate_env(path: Path):
    entries = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        match = re.match(r"^\s*(?:export\s+)?CLUSTER_SECRET\s*=\s*(.*)$", line)
        if match:
            try:
                parts = shlex.split(match.group(1), comments=True, posix=True)
            except ValueError:
                parts = []
            entries.append(parts[0] if len(parts) == 1 else "")
    secret = entries[0] if len(entries) == 1 else ""
    placeholders = ("dfsha-dev-secret", "cambia-", "cambiar", "change-me", "changeme",
                    "replace", "reemplaza", "placeholder", "your-secret", "example")
    if (len(secret) < 32 or len(set(secret)) < 8 or "$" in secret
            or any(word in secret.lower() for word in placeholders)):
        raise SetupError(
            ".env debe contener un único CLUSTER_SECRET literal, largo y aleatorio. "
            "Sustituye el valor de ejemplo antes del primer arranque. Si ya hay datos, "
            "restaura el secreto original: cambiarlo impide descifrarlos. No se modificó .env."
        )
    return secret


def local_data_exists(root: Path) -> bool:
    candidates = [root / "data", root / "volumes"]
    candidates.extend(p for p in root.iterdir() if p.is_dir() and p.name.endswith("_data"))
    return any(p.is_dir() and any(p.iterdir()) for p in candidates)


def docker_data_exists(root: Path) -> bool:
    """consulta los volúmenes de compose sin abrirlos ni cambiar su contenido"""
    project = os.environ.get("COMPOSE_PROJECT_NAME") or re.sub(r"[^a-z0-9_-]", "", root.name.lower()).lstrip("-_")
    if not project:
        raise SetupError("Define COMPOSE_PROJECT_NAME para identificar los volúmenes del proyecto.")
    try:
        result = subprocess.run(
            ["docker", "volume", "ls", "--filter", f"label=com.docker.compose.project={project}",
             "--format", "{{.Name}}"], capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SetupError("No se pudieron comprobar los volúmenes Docker; inicia Docker y vuelve a ejecutar scripts/start.sh.") from exc
    return bool(result.stdout.strip())


def prepare_env(root: Path, *, existing_data: bool = False, admin: bool = False) -> bool:
    """devuelve True si crea .env, un .env válido siempre se conserva igual byte a byte"""
    env = root / ".env"
    if env.exists():
        secret = validate_env(env)
        if "CLUSTER_SECRET" in os.environ and os.environ["CLUSTER_SECRET"] != secret:
            raise SetupError(
                "CLUSTER_SECRET del entorno no coincide con .env y Docker Compose le daría prioridad. "
                "Retira esa variable o restaura el secreto original antes de arrancar."
            )
        os.chmod(env, 0o600)
        return False
    if "CLUSTER_SECRET" in os.environ:
        raise SetupError(
            "CLUSTER_SECRET ya está definido en el entorno pero falta .env. "
            "Restaura la configuración original, o retira la variable si este es un cluster nuevo."
        )
    if existing_data or local_data_exists(root):
        raise SetupError(
            "Hay datos persistentes y falta .env. Restaura .env con el CLUSTER_SECRET original; "
            "no se generó otra clave ni se modificaron los datos."
        )
    contents = (
        "# Secretos locales de DFSha. Conserva una copia segura junto con tus respaldos.\n"
        f"CLUSTER_SECRET={secrets.token_hex(32)}\n"
        "DATA_KEY=\n"
        f"ADMIN_PASSWORD={secrets.token_urlsafe(24) if admin else ''}\n"
    )
    try:
        fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        validate_env(env)  # otro arranque creó .env, nunca se sobrescribe
        os.chmod(env, 0o600)
        return False
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
        out.write(contents)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(env, 0o600)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--admin", action="store_true", help="crear contraseña admin aleatoria al crear .env")
    ap.add_argument("--existing-data", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--docker-checked", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()
    root = args.root.resolve()
    try:
        has_data = args.existing_data
        if not (root / ".env").exists() and not args.docker_checked:
            has_data = has_data or docker_data_exists(root)
        created = prepare_env(root, existing_data=has_data, admin=args.admin)
    except (SetupError, OSError) as exc:
        ap.exit(1, f"Error de configuración: {exc}\n")
    print(".env creado con un secreto nuevo; guárdalo de forma segura." if created else ".env válido conservado.")


if __name__ == "__main__":
    main()
