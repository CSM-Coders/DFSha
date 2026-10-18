"""configuración del control node (variables de entorno) y claves derivadas del secreto del cluster"""
import os
import logging

import dfsha_security as sec

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("controlnode")


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


# replicación y estado de los datanodes
REPLICATION_FACTOR = env_int("REPLICATION_FACTOR", 2)
MIN_REPLICAS = env_int("MIN_REPLICAS", 1)  # réplicas mínimas para confirmar una escritura
HEARTBEAT_TIMEOUT = env_int("HEARTBEAT_TIMEOUT", 15)  # sin heartbeat no se usa para e/s
REREPLICATE_AFTER = env_int("REREPLICATE_AFTER", 30)  # sin heartbeat se dan por perdidas sus réplicas
MONITOR_INTERVAL = env_int("MONITOR_INTERVAL", 10)
WARMUP = env_int("WARMUP", 12)  # al arrancar, el registro de datanodes tarda como un heartbeat en llenarse
PLACEMENT_BUCKET = env_int("PLACEMENT_BUCKET", 128 * 1024 * 1024)  # nodos con carga en la misma franja se tratan como iguales
PRUNE_AFTER = env_int("PRUNE_AFTER", 900)  # un nodo muerto tanto tiempo sale de las listas de réplicas (si ya sobran copias)
BALANCE_THRESHOLD = env_int("BALANCE_THRESHOLD_BYTES", 64 * 1024 * 1024)  # diferencia de carga entre nodos que dispara el rebalanceo
BALANCE_MOVES = env_int("BALANCE_MOVES_PER_CYCLE", 4)  # máximo de bloques que se mueven por ciclo del monitor

# archivos y sesiones
UPLOAD_TTL = env_int("UPLOAD_TTL", 600)  # un put sin commit expira
HANDLE_TTL = env_int("HANDLE_TTL", 60)  # una sesión open() sin keepalive expira y suelta sus locks
DEFAULT_BLOCK_SIZE = env_int("BLOCK_SIZE", 4 * 1024 * 1024)
MIN_BLOCK_SIZE = 64 * 1024
MAX_BLOCK_SIZE = 32 * 1024 * 1024
MAX_GRPC_MSG = 64 * 1024 * 1024
MAX_BLOCKS_PER_FILE = env_int("MAX_BLOCKS_PER_FILE", 65536)  # limita la memoria/log por archivo (256 gib con bloques de 4 mib)
MAX_PATH_LEN = 4096
MAX_NAME_LEN = 255

# seguridad
CLUSTER_SECRET = os.environ.get("CLUSTER_SECRET", "")
KEYS = sec.Keys(CLUSTER_SECRET)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # si se define, crea el usuario "admin"
TOKEN_TTL = env_int("TOKEN_TTL", 8 * 3600)  # duración de un token de sesión
BLOCK_TOKEN_TTL = env_int("BLOCK_TOKEN_TTL", 600)  # duración de un token de acceso a bloque
ALLOW_REGISTRATION = os.environ.get("ALLOW_REGISTRATION", "1") != "0"  # 0 = solo el usuario admin crea cuentas
RESERVED_USERS = {"admin"}  # nombres que nadie puede registrar por su cuenta
LOGIN_MAX_FAILS = env_int("LOGIN_MAX_FAILS", 5)  # intentos fallidos antes de bloquear el login
LOGIN_LOCK_SECONDS = env_int("LOGIN_LOCK_SECONDS", 300)

TLS_CERT, TLS_KEY, TLS_CA = (os.environ.get(k) for k in ("TLS_CERT", "TLS_KEY", "TLS_CA"))
TLS = bool(TLS_CERT and TLS_KEY and TLS_CA)
SCHEME = "https" if TLS else "http"


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# cluster raft
RAFT_SELF = os.environ.get("RAFT_SELF", "127.0.0.1:4321")  # host:puerto raft de este nodo
RAFT_PEERS = [p for p in os.environ.get("RAFT_PEERS", "").split(",") if p]
PEER_HOSTS = [p.rsplit(":", 1)[0] for p in RAFT_PEERS]
DATA_DIR = os.environ.get("DATA_DIR", "/data")
API_PORT = env_int("API_PORT", 8000)  # puerto rest de todos los control nodes (para el proxy)
