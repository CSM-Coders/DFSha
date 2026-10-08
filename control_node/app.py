"""
ControlNode: mantiene los metadatos del DFS (árbol de directorios, ubicación
de bloques por archivo) y coordina qué DataNodes recibe cada bloque.
No mueve datos: solo dice "quién tiene qué". La transferencia real de bloques
va directo Cliente <-> DataNode por gRPC.
"""
import time
import uuid
import hashlib
import secrets
import logging
from typing import Optional

import grpc
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

import storage
import dfsha_pb2
import dfsha_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("controlnode")

app = FastAPI(title="DFSha ControlNode")

# ---------------------------------------------------------------------------
# Persistencia: usuarios, directorios y archivos viven en SQLite (storage.py),
# montado en un volumen Docker, para sobrevivir a un reinicio del ControlNode.
# Lo que sigue en memoria (a propósito, es efímero por diseño):
#   - TOKENS de sesión
#   - DATANODES registrados (se repueblan solos en segundos vía heartbeat)
# ---------------------------------------------------------------------------

storage.init_db()
storage.seed_user("admin", hashlib.sha256(b"admin123").hexdigest())

TOKENS: dict[str, str] = {}  # token -> user
DATANODES: dict[str, dict] = {}   # node_id -> {address, used_bytes, last_seen}

REPLICATION_FACTOR = 2
HEARTBEAT_TIMEOUT = 15  # seg. sin heartbeat -> nodo se considera caído


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


def _current_user(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "falta token Bearer")
    token = authorization.removeprefix("Bearer ")
    user = TOKENS.get(token)
    if not user:
        raise HTTPException(401, "token inválido o expirado")
    return user


@app.post("/auth/login")
def login(req: LoginRequest):
    h = hashlib.sha256(req.password.encode()).hexdigest()
    if storage.get_user_hash(req.username) != h:
        raise HTTPException(401, "credenciales inválidas")
    token = secrets.token_hex(16)
    TOKENS[token] = req.username
    return {"token": token}


class RegisterRequest(BaseModel):
    username: str
    password: str


@app.post("/auth/register")
def register(req: RegisterRequest):
    h = hashlib.sha256(req.password.encode()).hexdigest()
    if not storage.create_user(req.username, h):
        raise HTTPException(409, "el usuario ya existe")
    return {"ok": True}


def _require_owner(meta: dict, user: str):
    """Cada usuario solo puede ver/gestionar sus propios archivos."""
    if meta["owner"] != user:
        raise HTTPException(403, "no tienes acceso a este archivo")


# ---------------------------------------------------------------------------
# Registro de DataNodes (llamado por cada DataNode cada N segundos)
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    node_id: str
    address: str
    internal_address: Optional[str] = None
    used_bytes: int = 0


@app.post("/datanodes/register")
def register_datanode(req: RegisterRequest):
    DATANODES[req.node_id] = {
        "address": req.address,
        "internal_address": req.internal_address or req.address,
        "used_bytes": req.used_bytes,
        "last_seen": time.time(),
    }
    return {"ok": True}


def _alive_datanodes() -> list[str]:
    now = time.time()
    alive = [
        node_id for node_id, info in DATANODES.items()
        if now - info["last_seen"] <= HEARTBEAT_TIMEOUT
    ]
    return alive


@app.get("/datanodes")
def list_datanodes():
    now = time.time()
    return {
        node_id: {**info, "alive": now - info["last_seen"] <= HEARTBEAT_TIMEOUT}
        for node_id, info in DATANODES.items()
    }


def _pick_replicas(exclude: list[str] = None) -> list[str]:
    """Balanceo simple: ordena nodos vivos por espacio usado y toma los N con menos uso."""
    exclude = exclude or []
    candidates = [
        (node_id, info) for node_id, info in DATANODES.items()
        if node_id in _alive_datanodes() and node_id not in exclude
    ]
    candidates.sort(key=lambda kv: kv[1]["used_bytes"])
    chosen = candidates[:REPLICATION_FACTOR]
    if len(chosen) < REPLICATION_FACTOR:
        raise HTTPException(503, f"no hay suficientes DataNodes vivos (se necesitan {REPLICATION_FACTOR})")
    return [DATANODES[node_id]["address"] for node_id, _ in chosen]


# ---------------------------------------------------------------------------
# Gestión del filesystem (RF1)
# ---------------------------------------------------------------------------

class PathRequest(BaseModel):
    path: str


@app.post("/mkdir")
def mkdir(req: PathRequest, authorization: str = Header(None)):
    _current_user(authorization)
    storage.add_dir(req.path.rstrip("/") or "/")
    return {"ok": True}


@app.post("/rmdir")
def rmdir(req: PathRequest, authorization: str = Header(None)):
    _current_user(authorization)
    path = req.path.rstrip("/")
    if storage.has_children(path):
        raise HTTPException(400, "directorio no vacío")
    storage.remove_dir(path)
    return {"ok": True}


@app.get("/ls")
def ls(path: str = "/", authorization: str = Header(None)):
    user = _current_user(authorization)
    prefix = path.rstrip("/")
    all_dirs = storage.list_dirs()
    all_files = storage.list_files()
    dirs = [d for d in all_dirs if d != prefix and d.startswith(prefix + "/") and "/" not in d[len(prefix) + 1:]]
    files = [
        {"path": f, "size": meta["size"], "status": meta["status"]}
        for f, meta in all_files.items()
        if meta["owner"] == user and f.startswith(prefix + "/") and "/" not in f[len(prefix) + 1:]
    ]
    return {"dirs": dirs, "files": files}


def _delete_blocks_from_datanodes(blocks: list[dict]):
    """Borra cada réplica de cada bloque en su DataNode (best-effort: si un
    nodo está caído, el bloque queda huérfano ahí, pero como el metadato ya
    se elimina de todos modos, nunca más es alcanzable desde el DFS).

    Los bloques guardan la dirección "de cliente" (NODE_ADDR, ej. localhost:600X,
    pensada para un cliente fuera de Docker). El ControlNode corre dentro de la
    red de Docker, así que debe usar en cambio internal_address (ej. datanode1:6000)
    para llegar al mismo nodo."""
    addr_to_internal = {info["address"]: info["internal_address"] for info in DATANODES.values()}
    for block in blocks:
        for addr in block["replicas"]:
            target = addr_to_internal.get(addr, addr)
            try:
                with grpc.insecure_channel(target) as channel:
                    stub = dfsha_pb2_grpc.DataNodeStub(channel)
                    stub.DeleteBlock(dfsha_pb2.BlockId(block_id=block["block_id"]), timeout=5)
            except grpc.RpcError as e:
                log.warning("no se pudo borrar bloque %s en %s: %s", block["block_id"], target, e.details())


@app.post("/rm")
def rm(req: PathRequest, authorization: str = Header(None)):
    user = _current_user(authorization)
    meta = storage.get_file(req.path)
    if meta is None:
        raise HTTPException(404, "archivo no existe")
    _require_owner(meta, user)
    _delete_blocks_from_datanodes(meta["blocks"])
    storage.delete_file(req.path)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Transferencia de archivos (RF2): init -> cliente escribe bloques directo
# a los DataNodes por gRPC -> complete
# ---------------------------------------------------------------------------

class InitUploadRequest(BaseModel):
    path: str
    size: int
    block_size: int = 4 * 1024 * 1024  # 4 MB por defecto


@app.post("/files/init")
def init_upload(req: InitUploadRequest, authorization: str = Header(None)):
    user = _current_user(authorization)

    num_blocks = max(1, -(-req.size // req.block_size))  # ceil div
    blocks = []
    used_nodes_this_file = []
    for i in range(num_blocks):
        replicas = _pick_replicas()
        block_id = f"{uuid.uuid4().hex}"
        blocks.append({"block_id": block_id, "index": i, "replicas": replicas})
        used_nodes_this_file.extend(replicas)

    FILES_meta = {
        "size": req.size,
        "block_size": req.block_size,
        "blocks": blocks,
        "status": "uploading",
        "owner": user,
    }
    storage.save_file(req.path, FILES_meta)
    return {"path": req.path, "blocks": blocks}


class CompleteUploadRequest(BaseModel):
    path: str


@app.post("/files/complete")
def complete_upload(req: CompleteUploadRequest, authorization: str = Header(None)):
    user = _current_user(authorization)
    meta = storage.get_file(req.path)
    if meta is None:
        raise HTTPException(404, "archivo no existe")
    _require_owner(meta, user)
    storage.update_file_status(req.path, "ready")
    return {"ok": True}


@app.get("/files/{path:path}")
def get_file_metadata(path: str, authorization: str = Header(None)):
    user = _current_user(authorization)
    full_path = "/" + path
    meta = storage.get_file(full_path)
    if not meta or meta["status"] != "ready":
        raise HTTPException(404, "archivo no existe o no está completo")
    _require_owner(meta, user)
    return meta


@app.get("/health")
def health():
    return {"ok": True, "datanodes_alivos": len(_alive_datanodes())}
