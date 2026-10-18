"""autenticación y autorización del control node: contraseñas con scrypt, sesiones con tokens firmados (valen en cualquier nodo y se revocan subiendo la época del usuario), 2fa con totp, api keys y bloqueo temporal por intentos fallidos; cada archivo o directorio tiene dueño y acl por usuario o grupo ('r' lee/lista, 'rw' además crea/modifica/borra), los permisos se heredan hacia abajo y el dueño de un directorio manda sobre todo lo que tiene dentro (nivel 3)"""
import os
import hmac
import time
import base64
import struct
import hashlib
import posixpath
import threading
from collections import deque
from typing import Optional

from fastapi import HTTPException

import storage
import dfsha_security as sec
from config import KEYS, TOKEN_TTL, LOGIN_MAX_FAILS, LOGIN_LOCK_SECONDS, MAX_PATH_LEN, MAX_NAME_LEN

# contraseñas

def hash_password(password: str, salt: bytes = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


_DUMMY_HASH = hash_password("dummy-password-for-timing")


def verify_password(password: str, stored: Optional[str]) -> bool:
    known = True
    try:
        _, salt_hex, digest_hex = stored.split("$")
    except (ValueError, AttributeError):
        # usuario que no existe: gastamos el mismo cpu para no mostrar si existe
        _, salt_hex, digest_hex = _DUMMY_HASH.split("$")
        known = False
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                               n=2 ** 14, r=8, p=1, dklen=32).hex()
    return hmac.compare_digest(candidate, digest_hex) and known


# sesiones

def make_token(username: str) -> str:
    """token de sesión firmado con la época actual del usuario (subirla revoca todas las sesiones)"""
    u = storage.get_user(username)
    return sec.make_session_token(KEYS, username, u["epoch"] if u else 0, TOKEN_TTL)


def current_user(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "falta token Bearer")
    parsed = sec.parse_session_token(KEYS, authorization.removeprefix("Bearer "))
    if parsed:
        user = storage.get_user(parsed[0])
        if user and user["epoch"] == parsed[1]:
            return parsed[0]
    raise HTTPException(401, "token inválido, vencido o revocado")


# bloqueo por intentos fallidos (estado blando del líder)

_fails: dict[str, deque] = {}
_fails_lock = threading.Lock()


def check_login_allowed(name: str):
    now = time.time()
    with _fails_lock:
        q = _fails.get(name)
        while q and now - q[0] > LOGIN_LOCK_SECONDS:
            q.popleft()
        if q and len(q) >= LOGIN_MAX_FAILS:
            wait = int(LOGIN_LOCK_SECONDS - (now - q[0])) + 1
            raise HTTPException(429, f"demasiados intentos fallidos; reintenta en {wait} s",
                                headers={"Retry-After": str(wait)})


def record_login_failure(name: str):
    with _fails_lock:
        _fails.setdefault(name, deque()).append(time.time())


def clear_login_failures(name: str):
    with _fails_lock:
        _fails.pop(name, None)


# 2fa (totp, rfc 6238: hmac-sha1, pasos de 30 s, 6 dígitos)

_totp_used: dict[tuple, float] = {}


def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode()


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** 6
    return f"{code:06d}"


def totp_code(secret_b32: str, at: Optional[float] = None) -> str:
    return _hotp(secret_b32, int((at if at is not None else time.time()) // 30))


def verify_totp(username: str, secret_b32: str, code: Optional[str]) -> bool:
    """acepta el código del paso actual ±1 (por si el reloj está desfasado) y no deja reutilizar un código"""
    if not code or not code.isdigit() or len(code) != 6:
        return False
    step = int(time.time() // 30)
    now = time.time()
    for k in [k for k, t in _totp_used.items() if now - t > 120]:
        _totp_used.pop(k, None)
    for delta in (-1, 0, 1):
        if hmac.compare_digest(_hotp(secret_b32, step + delta), code):
            if (username, step + delta) in _totp_used:
                return False
            _totp_used[(username, step + delta)] = now
            return True
    return False


def totp_uri(username: str, secret_b32: str) -> str:
    return f"otpauth://totp/DFSha:{username}?secret={secret_b32}&issuer=DFSha"


# paths

def norm(path: str) -> str:
    if not path or "\x00" in path or not path.startswith("/"):
        raise HTTPException(400, "el path debe ser absoluto (empezar con /)")
    if len(path) > MAX_PATH_LEN or any(len(part) > MAX_NAME_LEN for part in path.split("/")):
        raise HTTPException(400, "path demasiado largo")
    return "/" + posixpath.normpath(path).lstrip("/")


def parent_of(path: str) -> str:
    return posixpath.dirname(path) or "/"


def ancestors(path: str) -> list[str]:
    """['/a/b/c', '/a/b', '/a', '/'] (incluye el propio path)"""
    out = [path]
    while path != "/":
        path = parent_of(path)
        out.append(path)
    return out


# permisos: nivel 0 = ninguno, 1 = leer/listar, 2 = escribir (crear, modificar, borrar), 3 = dueño

LEVELS = {"r": 1, "rw": 2}
OWNER = 3


def principals(user: str) -> list[str]:
    return ["user:" + user] + ["group:" + g for g in storage.groups_of(user)]


def inherited_level(dir_path: str, user: str, princ: Optional[list[str]] = None) -> int:
    """nivel que tiene el usuario sobre un directorio por ser dueño o por su acl o la de sus ancestros"""
    if dir_path == "/":
        return 2  # la raíz es de todos: listar y crear en ella
    chain = ancestors(dir_path)[:-1]  # sin '/'
    if any(o == user for o in storage.dir_owners(chain).values()):
        return OWNER
    perms = storage.acl_perms(chain, princ if princ is not None else principals(user))
    return max((LEVELS[p] for p in perms.values()), default=0)


def level_of(path: str, user: str, owner: Optional[str] = None, princ: Optional[list[str]] = None) -> int:
    """nivel del usuario sobre un archivo o directorio (`owner` si ya se sabe quién es el dueño del propio path)"""
    if path == "/":
        return 2
    if owner is None:
        owner = storage.get_dir_owner(path)
        if owner is None:
            f = storage.get_file(path)
            owner = f["owner"] if f else None
    if owner == user:
        return OWNER
    return inherited_level(path, user, princ)


def require_level(path: str, user: str, need: int, owner: Optional[str] = None, what: str = "este elemento") -> int:
    lvl = level_of(path, user, owner)
    if lvl < need:
        raise HTTPException(403, f"no tienes permiso {'de escritura' if need >= 2 else 'de lectura'} sobre {what}")
    return lvl


def require_dir(dir_path: str, user: str, need: int) -> int:
    """el directorio tiene que existir y el usuario necesita al menos `need` sobre él"""
    owner = storage.get_dir_owner(dir_path)
    if owner is None:
        raise HTTPException(404, f"el directorio {dir_path} no existe")
    return require_level(dir_path, user, need, owner=owner, what=f"el directorio {dir_path}")
