"""primitivas de seguridad compartidas por control node y data node: todas las claves salen del secreto del cluster (CLUSTER_SECRET) con hmac y una etiqueta por uso (session firma los tokens de sesión, block firma los tokens de acceso a bloques, node autentica a los datanodes ante los control nodes y disk es la clave aes-256-gcm para cifrar bloques en disco), así una clave comprometida para un uso no sirve para otro; un token de bloque autoriza una operación sobre un bloque por un tiempo corto ({b: block_id, o: r/w/d/x, e: expiración}) y el control node solo lo entrega después de revisar los permisos, por eso el datanode lo valida solo (como los block access tokens de hdfs)"""
import base64
import hashlib
import hmac
import json
import time
from typing import Optional

DEV_SECRET = "dfsha-insecure-dev-secret"


def _derive(secret: str, label: str) -> bytes:
    return hmac.new(secret.encode(), label.encode(), hashlib.sha256).digest()


class Keys:
    def __init__(self, secret: Optional[str]):
        self.insecure = not secret
        secret = secret or DEV_SECRET
        self.session = _derive(secret, "dfsha-session-token-v1")
        self.block = _derive(secret, "dfsha-block-token-v1")
        self.node = _derive(secret, "dfsha-node-auth-v1")
        self.disk = _derive(secret, "dfsha-disk-key-v1")


def _sign(key: bytes, payload: str) -> str:
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def _pack(key: bytes, data: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()
    return f"{payload}.{_sign(key, payload)}"


def _unpack(key: bytes, token: str) -> Optional[dict]:
    try:
        payload, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(key, payload)):
            return None
        return json.loads(base64.urlsafe_b64decode(payload.encode()))
    except (ValueError, TypeError, AttributeError):
        return None


# sesiones de usuario

def make_session_token(keys: Keys, user: str, epoch: int, ttl: float) -> str:
    return _pack(keys.session, {"u": user, "ep": epoch, "e": time.time() + ttl})


def parse_session_token(keys: Keys, token: str):
    """(usuario, época) si la firma es válida y no expiró, None si no"""
    d = _unpack(keys.session, token)
    if not d or d.get("e", 0) < time.time():
        return None
    return d["u"], d.get("ep", 0)


# tokens de acceso a bloques

def make_block_token(keys: Keys, block_id: str, op: str, ttl: float = 600) -> str:
    return _pack(keys.block, {"b": block_id, "o": op, "e": time.time() + ttl})


def verify_block_token(keys: Keys, token: Optional[str], block_id: str, ops: str) -> bool:
    """true si el token es auténtico, está vigente, es de este bloque y su operación está en `ops`"""
    if not token:
        return False
    d = _unpack(keys.block, token)
    return bool(d and d.get("b") == block_id and d.get("o") in ops and d.get("e", 0) >= time.time())


# autenticación de los datanodes ante el control node

def make_node_token(keys: Keys, node_id: str) -> str:
    return _sign(keys.node, "node:" + node_id)


def verify_node_token(keys: Keys, node_id: str, token: Optional[str]) -> bool:
    return bool(token) and hmac.compare_digest(token, make_node_token(keys, node_id))
