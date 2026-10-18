"""control node: guarda los metadatos del dfs (árbol de directorios y dónde está cada bloque) y coordina a los datanodes, no mueve datos de usuario porque los bloques van directo del cliente al datanode por grpc; los metadatos se replican con raft entre 3 control nodes (cualquiera atiende y los seguidores reenvían al líder), los bloques son inmutables y un archivo cambia de versión con un commit atómico (copy-on-write), una escritura vale si cada bloque queda en MIN_REPLICAS nodos y el monitor completa hasta REPLICATION_FACTOR, el sha256 de cada bloque vive en los metadatos y el cliente lo verifica al leer; los permisos (dueño + acl) los decide este nodo y entrega tokens de bloque que los datanodes verifican solos"""
import re
import time
import uuid
import random
import threading
from contextlib import asynccontextmanager
from typing import Optional

import grpc
import httpx
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

import storage
import access
import dfsha_pb2
import dfsha_pb2_grpc
import dfsha_security as sec
from auth_routes import router as auth_router
from cluster import cluster, Unavailable
from config import (
    log, REPLICATION_FACTOR, MIN_REPLICAS, HEARTBEAT_TIMEOUT, REREPLICATE_AFTER, MONITOR_INTERVAL, WARMUP,
    PLACEMENT_BUCKET, PRUNE_AFTER, BALANCE_THRESHOLD, BALANCE_MOVES, UPLOAD_TTL, HANDLE_TTL, DEFAULT_BLOCK_SIZE, MIN_BLOCK_SIZE, MAX_BLOCK_SIZE, MAX_GRPC_MSG,
    CLUSTER_SECRET, KEYS, ADMIN_PASSWORD, BLOCK_TOKEN_TTL, TLS, TLS_CERT, TLS_KEY, TLS_CA, SCHEME, read_file,
    MAX_BLOCKS_PER_FILE,
    RAFT_SELF, RAFT_PEERS, PEER_HOSTS, DATA_DIR, API_PORT,
)

# nombres que usan las pruebas unitarias
_hash_password, _verify_password, _norm = access.hash_password, access.verify_password, access.norm
_parent = access.parent_of

START_TIME = time.time()
HANDLE_SEEN: dict[str, float] = {}  # handle_id -> última actividad (lease, estado blando del líder)
_handle_lease_lock = threading.RLock()
DATANODES: dict[str, dict] = {}  # node_id -> {address, internal_address, used_bytes, last_seen}
_pending_replicas: set[str] = set()  # block_ids que se están copiando (no son huérfanos)
_reported_lost: set[str] = set()
_inventory_challenges: dict[str, dict] = {}
_inventory_lock = threading.RLock()

_ADDR_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}:\d{1,5}$")
_NODE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _tok(block_id: str, op: str) -> str:
    """token de acceso a bloque para el cliente (lo verifica el datanode)"""
    return sec.make_block_token(KEYS, block_id, op, BLOCK_TOKEN_TTL)


# grpc hacia los datanodes (control node -> datanode, puerto interno con mtls)

_GRPC_OPTS = [
    ("grpc.max_send_message_length", MAX_GRPC_MSG),
    ("grpc.max_receive_message_length", MAX_GRPC_MSG),
    ("grpc.initial_reconnect_backoff_ms", 500),
    ("grpc.max_reconnect_backoff_ms", 3000),
    ("grpc.dns_min_time_between_resolutions_ms", 1000),
]
_channels: dict[str, grpc.Channel] = {}
_channels_lock = threading.Lock()
_RPC_OPS = {"DeleteBlock": "d", "ReplicateBlock": "x", "ReadBlock": "r"}


def _stub(address: str) -> dfsha_pb2_grpc.DataNodeStub:
    with _channels_lock:
        ch = _channels.get(address)
        if ch is None:
            if TLS:
                creds = grpc.ssl_channel_credentials(root_certificates=read_file(TLS_CA),
                                                     private_key=read_file(TLS_KEY),
                                                     certificate_chain=read_file(TLS_CERT))
                ch = grpc.secure_channel(address, creds, options=_GRPC_OPTS)
            else:
                ch = grpc.insecure_channel(address, options=_GRPC_OPTS)
            _channels[address] = ch
    return dfsha_pb2_grpc.DataNodeStub(ch)


def _drop_channel(address: str):
    with _channels_lock:
        ch = _channels.pop(address, None)
    if ch:
        ch.close()


def _rpc(node_id: str, address: str, method: str, request, timeout: float = 5):
    """llamada grpc del control node a un datanode: dice con qué nodo cree hablar y manda un token para ese bloque, si el canal guardado apunta a otro nodo (ip reasignada) o a un contenedor reiniciado se descarta y se reintenta una vez con uno nuevo"""
    meta = (("x-dfsha-expect-node", node_id),
            ("x-dfsha-token", sec.make_block_token(KEYS, request.block_id, _RPC_OPS[method], 120)))
    for attempt in (1, 2):
        try:
            return getattr(_stub(address), method)(request, timeout=timeout, metadata=meta)
        except grpc.RpcError as e:
            if attempt == 1 and e.code() in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.FAILED_PRECONDITION):
                _drop_channel(address)
                continue
            raise


# estado de los datanodes y colocación de bloques

def _alive_nodes(max_age: float = None) -> dict[str, dict]:
    """nodos con heartbeat reciente (para e/s) o con max_age propio (para decidir pérdidas)"""
    limit = HEARTBEAT_TIMEOUT if max_age is None else max_age
    now = time.time()
    return {nid: info for nid, info in list(DATANODES.items()) if now - info["last_seen"] <= limit}


def _check_replicas_visible(blocks: list[dict]):
    """justo después de arrancar todavía no se conocen todos los datanodes, para no decir 'sin réplicas' por error se pide al cliente que reintente"""
    if time.time() - START_TIME < WARMUP and any(not b["replicas"] for b in blocks):
        raise HTTPException(503, "el ControlNode acaba de arrancar y aún reúne a los DataNodes; reintenta")


def _delete_blocks(blocks: list[dict]):
    """borra cada réplica en su datanode (si puede), si un nodo está caído el bloque queda huérfano ahí y el gc lo recoge cuando vuelva"""
    for b in blocks:
        for nid in b["nodes"]:
            info = DATANODES.get(nid)
            if not info:
                log.warning("bloque %s: nodo %s desconocido, se limpiará por GC de huérfanos", b["block_id"][:8], nid)
                continue
            try:
                _rpc(nid, info["internal_address"], "DeleteBlock", dfsha_pb2.BlockId(block_id=b["block_id"]))
            except grpc.RpcError as e:
                log.warning("no se pudo borrar bloque %s en %s: %s", b["block_id"], nid, e.details())


def _place_blocks(sizes: list[int], start_index: int = 0) -> list[dict]:
    """reparte bloques entre los nodos vivos: los de carga parecida (misma franja de PLACEMENT_BUCKET bytes) se tratan como iguales y se elige al azar para que los bloques de un archivo queden en todos los nodos, y la carga se actualiza bloque a bloque porque used_bytes solo cambia con el heartbeat y todo caería en los mismos nodos"""
    alive = _alive_nodes()
    k = min(REPLICATION_FACTOR, len(alive))
    if k < MIN_REPLICAS:
        raise HTTPException(503, f"no hay suficientes DataNodes vivos (mínimo {MIN_REPLICAS})")
    load = {nid: info["used_bytes"] for nid, info in alive.items()}
    blocks = []
    for i, bsize in enumerate(sizes):
        chosen = sorted(load, key=lambda n: (load[n] // PLACEMENT_BUCKET, random.random()))[:k]
        for n in chosen:
            load[n] += bsize
        blocks.append({"block_id": uuid.uuid4().hex, "index": start_index + i, "size": bsize,
                       "nodes": chosen, "checksum": None})
    return blocks


def _plan_blocks(size: int, block_size: int) -> list[dict]:
    num_blocks = max(1, -(-size // block_size))
    sizes = [min(block_size, size - i * block_size) if size else 0 for i in range(num_blocks)]
    return _place_blocks(sizes)


def _release_blocks(blocks: list[dict]):
    """borra de los datanodes los bloques que ya no usa ninguna versión del archivo, menos los que todavía necesita alguna sesión abierta (esos los recoge el gc cuando se liberen)"""
    protected = storage.handle_block_ids()
    unique = {b["block_id"]: b for b in blocks if b["block_id"] not in protected}
    _delete_blocks(list(unique.values()))


# monitor en segundo plano: re-replica, recorta copias de más y limpia uploads viejos

def _copy_block(path: str, block: dict, source: str, target: str, alive: dict) -> bool:
    """le dice a `target` que copie el bloque desde `source` y si sale bien lo registra como réplica, devuelve True si quedó registrada"""
    with _inventory_lock:
        _pending_replicas.add(block["block_id"])
        # un reporte tomado antes de esta reparación no puede invalidar la copia nueva, aunque llegue después de que termine el rpc
        pending = _inventory_challenges.get(target)
        if pending:
            pending["expected"].discard(block["block_id"])
    try:
        ack = _rpc(target, alive[target]["internal_address"], "ReplicateBlock",
                   dfsha_pb2.ReplicateRequest(
                       block_id=block["block_id"],
                       source_address=alive[source]["internal_address"],
                       source_node=source,
                       source_token=sec.make_block_token(KEYS, block["block_id"], "r", 180),
                       checksum=block["checksum"] or "",
                   ), timeout=120)
        if not ack.success:
            log.warning("falló copiar %s a %s: %s", block["block_id"][:8], target, ack.message)
            return False
        if cluster.write("update_block_nodes", path=path, block_id=block["block_id"], add=target):
            return True
        _rpc(target, alive[target]["internal_address"], "DeleteBlock", dfsha_pb2.BlockId(block_id=block["block_id"]))
        return False  # el archivo se borró mientras tanto
    except grpc.RpcError as e:
        log.warning("falló copiar %s a %s: %s", block["block_id"][:8], target, e.details())
        return False
    finally:
        with _inventory_lock:
            _pending_replicas.discard(block["block_id"])


def _re_replicate(path: str, block: dict, live: list[str], alive: dict) -> int:
    needed = REPLICATION_FACTOR - len(live)
    candidates = sorted(
        (n for n in alive if n not in block["nodes"]),
        key=lambda n: (alive[n]["used_bytes"], random.random()),
    )
    sources = [n for n in live if n in alive]
    done = 0
    for target in candidates[:needed] if sources else []:
        source = random.choice(sources)
        if _copy_block(path, block, source, target, alive):
            log.info("re-replicado %s: %s -> %s", block["block_id"][:8], source, target)
            done += 1
    return done


def plan_moves(used: dict, blocks: list, threshold: int, max_moves: int) -> list:
    """planifica qué bloques mover del nodo más cargado al menos cargado (como el balancer de hdfs): `blocks` = [(path, block)] y devuelve [(path, block, origen, destino)], solo mueve si la diferencia pasa `threshold` y nunca un bloque mayor que la mitad de esa diferencia para no oscilar"""
    used = dict(used)
    moves, taken = [], set()
    for _ in range(max_moves):
        if len(used) < 2:
            break
        src = max(used, key=used.get)
        dst = min(used, key=used.get)
        gap = used[src] - used[dst]
        if gap <= threshold:
            break
        fits = [(p, b) for p, b in blocks
                if src in b["nodes"] and dst not in b["nodes"] and b["block_id"] not in taken
                and 0 < b["size"] <= gap // 2]
        if not fits:
            break
        path, block = max(fits, key=lambda pb: pb[1]["size"])
        taken.add(block["block_id"])
        used[src] -= block["size"]
        used[dst] += block["size"]
        moves.append((path, block, src, dst))
    return moves


def _rebalance(alive: dict, files: dict):
    """si los nodos están muy desparejos (por ejemplo se añadió uno vacío) mueve unos pocos bloques por ciclo: copia al destino, registra la réplica y solo después quita la del origen (el factor nunca baja)"""
    used = {n: info["used_bytes"] for n, info in alive.items()}
    blocks = [(p, b) for p, meta in files.items() for b in meta["blocks"]]
    for path, block, src, dst in plan_moves(used, blocks, BALANCE_THRESHOLD, BALANCE_MOVES):
        if not _copy_block(path, block, src, dst, alive):
            continue
        if cluster.write("update_block_nodes", path=path, block_id=block["block_id"], remove=src):
            try:
                _rpc(src, alive[src]["internal_address"], "DeleteBlock", dfsha_pb2.BlockId(block_id=block["block_id"]))
            except grpc.RpcError:
                pass  # queda huérfano y lo recoge el gc
            log.info("rebalanceado %s: %s -> %s", block["block_id"][:8], src, dst)


def _trim(path: str, block: dict, live: list[str], alive: dict):
    extra = len(live) - REPLICATION_FACTOR
    victims = sorted(live, key=lambda n: -alive[n]["used_bytes"])[:extra]
    for v in victims:
        if cluster.write("update_block_nodes", path=path, block_id=block["block_id"], remove=v):
            try:
                _rpc(v, alive[v]["internal_address"], "DeleteBlock", dfsha_pb2.BlockId(block_id=block["block_id"]))
                log.info("recortada réplica sobrante de %s en %s", block["block_id"][:8], v)
            except grpc.RpcError:
                pass


def _close_handle(handle_id: str, stale_before: float = None):
    with _handle_lease_lock:
        if stale_before is not None and HANDLE_SEEN.setdefault(handle_id, time.time()) >= stale_before:
            return None
        h = cluster.write("delete_handle", handle_id=handle_id)
        HANDLE_SEEN.pop(handle_id, None)
    if h:
        _release_blocks(h["allocated"])  # bloques asignados que nunca se publicaron
    return h


def _reconcile_once():
    now = time.time()
    live_handles = set(storage.handle_ids())
    with _handle_lease_lock:
        for handle_id in list(HANDLE_SEEN):
            if handle_id not in live_handles:
                HANDLE_SEEN.pop(handle_id, None)
    for handle_id in live_handles:
        # un líder recién elegido no sabe cuál fue la última actividad, así que le da a cada sesión un ttl completo
        if _close_handle(handle_id, stale_before=now - HANDLE_TTL):
            log.info("sesión expirada %s: se liberan sus locks y bloques sin publicar", handle_id[:8])
    for upload_id in storage.stale_uploads(now - UPLOAD_TTL):
        up = cluster.write("delete_upload", upload_id=upload_id, stale_before=now - UPLOAD_TTL)
        if up:
            log.info("upload expirado %s (%s): se liberan sus bloques", upload_id[:8], up["path"])
            _delete_blocks(up["blocks"])

    alive = _alive_nodes()
    holders = _alive_nodes(REREPLICATE_AFTER)  # nodos que todavía se consideran dueños de sus réplicas
    if not alive:
        return
    files = storage.list_files()
    repaired = 0
    for path, meta in files.items():
        for b in meta["blocks"]:
            live = [n for n in b["nodes"] if n in holders]
            if not live:
                if b["block_id"] not in _reported_lost:
                    _reported_lost.add(b["block_id"])
                    log.error("BLOQUE SIN RÉPLICAS DISPONIBLES: %s de %s", b["block_id"], path)
                continue
            _reported_lost.discard(b["block_id"])
            if len(live) < REPLICATION_FACTOR:
                repaired += _re_replicate(path, b, live, alive) or 1
            else:
                for n in b["nodes"]:  # poda: un nodo muerto hace mucho ya no cuenta si sobran copias sanas
                    seen = DATANODES.get(n, {}).get("last_seen")
                    if n not in holders and seen is not None and now - seen > PRUNE_AFTER:
                        cluster.write("update_block_nodes", path=path, block_id=b["block_id"], remove=n)
                        log.info("podado el nodo muerto %s de las réplicas de %s", n, b["block_id"][:8])
                if len(live) > REPLICATION_FACTOR:
                    _trim(path, b, [n for n in live if n in alive], alive)
    if not repaired:  # primero se repara y solo con todo sano se rebalancea
        _rebalance(alive, files)


def _monitor_loop(stop: threading.Event):
    stop.wait(HEARTBEAT_TIMEOUT)  # darle tiempo a los datanodes para que se registren
    while not stop.wait(MONITOR_INTERVAL):
        if not cluster.can_serve():  # solo el líder maneja réplicas, sesiones y limpieza
            continue
        try:
            _reconcile_once()
        except Exception:
            log.exception("error en el monitor de réplicas")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if KEYS.insecure:
        log.warning("CLUSTER_SECRET no está definido: se usa una clave de desarrollo INSEGURA")
    if not TLS:
        log.warning("TLS desactivado (faltan TLS_CERT/TLS_KEY/TLS_CA): el tráfico va en claro")
    cluster.start(RAFT_SELF, RAFT_PEERS, DATA_DIR, password=CLUSTER_SECRET or None)
    stop = threading.Event()
    threading.Thread(target=_monitor_loop, args=(stop,), daemon=True, name="monitor").start()
    if ADMIN_PASSWORD:
        threading.Thread(target=_seed_admin, daemon=True, name="seed-admin").start()
    _app.state.proxy = httpx.AsyncClient(timeout=60, verify=TLS_CA if TLS else True)
    yield
    stop.set()
    cluster.stop()
    await _app.state.proxy.aclose()


def _seed_admin():
    while not cluster.can_serve():
        time.sleep(0.5)
        if not cluster.started:
            return
    try:
        cluster.write("register_user", username="admin", password_hash=access.hash_password(ADMIN_PASSWORD))
    except Unavailable:
        pass


app = FastAPI(title="DFSha ControlNode", lifespan=lifespan)
app.include_router(auth_router)

# rutas que cada control node atiende solo (el resto se reenvía al líder)
_LOCAL_PREFIXES = ("/health", "/raft", "/datanodes", "/docs", "/openapi.json", "/redoc")
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
               "trailers", "transfer-encoding", "upgrade", "host", "content-length"}


@app.middleware("http")
async def leader_proxy(request: Request, call_next):
    """un seguidor reenvía la petición al líder y el líder solo atiende después de confirmar su barrera"""
    if request.url.path.startswith(_LOCAL_PREFIXES) or not cluster.started:
        return await call_next(request)
    retry = {"Retry-After": "1"}
    if cluster.can_serve():
        return await call_next(request)
    if cluster.is_leader():
        return JSONResponse({"detail": "el líder aún se está sincronizando; reintenta"}, 503, headers=retry)
    host = cluster.leader_host()
    if not host:
        return JSONResponse({"detail": "sin líder (elección en curso); reintenta"}, 503, headers=retry)
    if request.headers.get("x-dfsha-forwarded"):
        return JSONResponse({"detail": "este nodo no es el líder; reintenta"}, 503,
                            headers={**retry, "X-DFSha-Not-Leader": "1"})
    headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
    headers["x-dfsha-forwarded"] = "1"
    path = request.scope["raw_path"].decode() + (("?" + request.url.query) if request.url.query else "")
    body = await request.body()
    # el "líder conocido" de un seguidor puede estar atrasado, si ese nodo dice que ya no es líder se prueba con los demás
    me = RAFT_SELF.rsplit(":", 1)[0]
    candidates = [host] + [h for h in PEER_HOSTS if h != host and h != me]
    last = "ningún par respondió"
    for h in candidates:
        try:
            r = await request.app.state.proxy.request(request.method, f"{SCHEME}://{h}:{API_PORT}{path}",
                                                      content=body, headers=headers)
        except httpx.HTTPError as e:
            last = f"{h}: {e}"
            continue
        if r.status_code == 503 and r.headers.get("x-dfsha-not-leader"):
            continue
        out_headers = {k: v for k, v in r.headers.items() if k.lower() == "retry-after"}
        return Response(r.content, r.status_code, headers=out_headers,
                        media_type=r.headers.get("content-type", "application/json"))
    return JSONResponse({"detail": f"no se encontró al líder ({last})"}, 503, headers=retry)


@app.exception_handler(Unavailable)
async def _unavailable(_req: Request, exc: Unavailable):
    return JSONResponse({"detail": str(exc)}, 503, headers={"Retry-After": "1"})


@app.exception_handler(storage.Conflict)
async def _conflict(_req: Request, exc: storage.Conflict):
    return JSONResponse({"detail": str(exc)}, 409)


@app.exception_handler(storage.Gone)
async def _gone(_req: Request, exc: storage.Gone):
    return JSONResponse({"detail": str(exc)}, 404)


@app.exception_handler(storage.Locked)
async def _locked(_req: Request, exc: storage.Locked):
    return JSONResponse({"detail": str(exc)}, 423)


# registro y heartbeat de los datanodes

class NodeRegisterRequest(BaseModel):
    node_id: str
    address: str  # la usan los clientes (puerto público, puede ser localhost:600X)
    internal_address: Optional[str] = None  # la usan el control node y otros datanodes (puerto interno, mtls)
    used_bytes: int = 0
    block_ids: Optional[list[str]] = None  # reporte de bloques (cada cierto tiempo)
    corrupt_blocks: Optional[list[str]] = None  # bloques que el nodo puso en cuarentena por estar corruptos
    inventory_id: Optional[str] = Field(default=None, max_length=64)  # identidad de este arranque
    inventory_generation: int = Field(default=0, ge=0)
    inventory_request: Optional[str] = Field(default=None, max_length=64)
    inventory_blocks: Optional[list[str]] = None  # inventario completo, tomado después de recibir el desafío


def _expected_replicas(node_id: str) -> set[str]:
    return {b["block_id"] for meta in storage.list_files().values()
            for b in meta["blocks"] if node_id in b["nodes"]}


def _check_inventory(req: NodeRegisterRequest) -> Optional[str]:
    """reconcilia solo las copias que ya se esperaban antes de pedir el inventario: comparar un heartbeat viejo con el estado de ahora podría descartar bloques recién escritos, por eso el desafío fija el orden (primero la foto de los metadatos y luego el escaneo del disco) sin depender de relojes; un inventario vacío es válido y el estado es local, así que tras un failover se pide un desafío nuevo antes de retirar copias"""
    with _inventory_lock:
        if not cluster.can_serve():
            _inventory_challenges.pop(req.node_id, None)
            return None
        if not req.inventory_id:  # compatibilidad con nodos viejos, no se deduce que faltan bloques
            return None
        pending = _inventory_challenges.get(req.node_id)
        if pending and pending["boot"] != req.inventory_id:
            pending = None
            _inventory_challenges.pop(req.node_id, None)
        if (pending and req.inventory_request == pending["nonce"]
                and req.inventory_generation > pending["generation"]
                and req.inventory_blocks is not None):
            present = set(req.inventory_blocks)
            if any(not re.fullmatch(r"[0-9a-f]{32}", bid) for bid in present):
                raise HTTPException(400, "inventario de bloques inválido")
            missing = pending["expected"] - present - set(_pending_replicas)
            missing &= _expected_replicas(req.node_id)
            if missing:
                cluster.write("drop_missing_replicas", node_id=req.node_id, block_ids=sorted(missing))
                log.warning("inventario de %s: retiradas %d réplicas ausentes; se repondrán",
                            req.node_id, len(missing))
            pending = None
        if pending is None:
            pending = {"nonce": uuid.uuid4().hex, "boot": req.inventory_id,
                       "generation": req.inventory_generation,
                       "expected": _expected_replicas(req.node_id)}
            _inventory_challenges[req.node_id] = pending
        return pending["nonce"]


@app.post("/datanodes/register")
def register_datanode(req: NodeRegisterRequest, x_dfsha_node_token: str = Header(None)):
    if not sec.verify_node_token(KEYS, req.node_id, x_dfsha_node_token):
        raise HTTPException(401, "DataNode no autenticado (token de nodo inválido)")
    if not (_NODE_RE.match(req.node_id) and _ADDR_RE.match(req.address)
            and (req.internal_address is None or _ADDR_RE.match(req.internal_address))):
        raise HTTPException(400, "node_id o direcciones con formato inválido")
    DATANODES[req.node_id] = {
        "address": req.address,
        "internal_address": req.internal_address or req.address,
        "used_bytes": req.used_bytes,
        "last_seen": time.time(),
    }
    delete_blocks = []
    if req.block_ids and cluster.can_serve():  # solo el líder (con estado al día) ordena borrados
        # si los metadatos están vacíos (por ejemplo se perdió el volumen del control) no borramos nada, porque podríamos perder datos que todavía se pueden recuperar
        if storage.has_users():
            known = storage.all_block_ids() | set(_pending_replicas)
            delete_blocks = [b for b in req.block_ids if b not in known]
        else:
            log.warning("metadatos vacíos: se omite la limpieza de huérfanos de %s", req.node_id)
    corrupt_ack = []
    if req.corrupt_blocks and cluster.can_serve():
        for bid in req.corrupt_blocks:
            if re.fullmatch(r"[0-9a-f]{32}", bid):
                paths = cluster.write("drop_replica", block_id=bid, node_id=req.node_id)
                log.warning("réplica corrupta de %s en %s retirada de %s; se repondrá en otro nodo",
                            bid[:8], req.node_id, paths or "(ningún archivo)")
                corrupt_ack.append(bid)
    inventory_request = _check_inventory(req)
    return {"ok": True, "leader": cluster.can_serve(), "delete_blocks": delete_blocks,
            "corrupt_ack": corrupt_ack, "inventory_request": inventory_request}


@app.get("/datanodes")
def list_datanodes(authorization: str = Header(None)):
    access.current_user(authorization)
    now = time.time()
    return {
        nid: {k: v for k, v in info.items() if k != "internal_address"}
        | {"alive": now - info["last_seen"] <= HEARTBEAT_TIMEOUT}
        for nid, info in list(DATANODES.items())
    }


# manejo del filesystem (rf1)

class PathRequest(BaseModel):
    path: str


@app.post("/mkdir")
def mkdir(req: PathRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    path = access.norm(req.path)
    if path == "/":
        return {"ok": True}
    access.require_dir(access.parent_of(path), user, 2)
    if storage.get_file(path):
        raise HTTPException(409, "ya existe un archivo con ese nombre")
    if not cluster.write("add_dir", path=path, owner=user) and storage.get_dir_owner(path) != user:
        raise HTTPException(409, "el directorio ya existe y pertenece a otro usuario")
    return {"ok": True}


@app.post("/rmdir")
def rmdir(req: PathRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    path = access.norm(req.path)
    if path == "/":
        raise HTTPException(400, "no se puede borrar la raíz")
    owner = storage.get_dir_owner(path)
    if owner is None:
        raise HTTPException(404, "el directorio no existe")
    access.require_level(path, user, 2, owner=owner, what="este directorio")
    if storage.has_children(path):
        raise HTTPException(409, "directorio no vacío")
    cluster.write("remove_dir", path=path)
    return {"ok": True}


@app.get("/ls")
def ls(path: str = "/", authorization: str = Header(None)):
    """lista un directorio mostrando solo lo que el usuario puede ver (suyo o compartido con él)"""
    user = access.current_user(authorization)
    path = access.norm(path)
    lvl = access.require_dir(path, user, 1)
    princ = access.principals(user)
    inherited = 0 if path == "/" else lvl  # la raíz no le da nada a sus hijos, cada hijo se evalúa por separado
    dirs, files = storage.child_dirs(path), storage.child_files(path)
    acl = storage.acl_perms([c["path"] for c in dirs + files], princ)

    def perm(c):
        level = max(inherited, access.OWNER if c["owner"] == user else 0, access.LEVELS.get(acl.get(c["path"]), 0))
        return level

    return {
        "dirs": sorted(c["path"] for c in dirs if perm(c) >= 1),
        "files": sorted(({"path": c["path"], "size": c["size"], "owner": c["owner"], "mtime": c["mtime"], "version": c["version"],
                          "perm": {1: "r", 2: "rw", 3: "owner"}[perm(c)]} for c in files if perm(c) >= 1),
                        key=lambda f: f["path"]),
    }


@app.post("/rm")
def rm(req: PathRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    path = access.norm(req.path)
    meta = storage.get_file(path)
    if meta is None:
        raise HTTPException(404, "archivo no existe" if storage.get_dir_owner(path) is None
                            else "es un directorio, usa rmdir")
    access.require_level(path, user, 2, owner=meta["owner"], what="este archivo")
    try:
        removed = cluster.write("delete_file", path=path)  # primero el metadato, si algo falla solo quedan bloques huérfanos
    except storage.Locked:
        raise HTTPException(423, "el archivo está bloqueado por otra sesión")
    if removed:
        _release_blocks(removed["blocks"])
    return {"ok": True}


class MoveRequest(BaseModel):
    src: str
    dst: str


@app.post("/mv")
def mv(req: MoveRequest, authorization: str = Header(None)):
    """mueve o renombra un archivo o directorio (con su contenido, permisos y sesiones abiertas)"""
    user = access.current_user(authorization)
    src, dst = access.norm(req.src), access.norm(req.dst)
    if src == "/" or dst == "/":
        raise HTTPException(400, "no se puede mover la raíz")
    owner = storage.get_dir_owner(src)
    if owner is None:
        f = storage.get_file(src)
        if f is None:
            raise HTTPException(404, "el origen no existe")
        owner = f["owner"]
    elif access.parent_of(src) == "/" and storage.user_exists(src[1:]):
        raise HTTPException(403, "no se puede mover ni renombrar el directorio home de un usuario")
    access.require_level(src, user, 2, owner=owner, what="el origen")
    if storage.get_dir_owner(access.parent_of(dst)) is None:
        raise HTTPException(404, f"el directorio destino {access.parent_of(dst)} no existe")
    access.require_dir(access.parent_of(dst), user, 2)
    res = cluster.write("rename_path", src=src, dst=dst)
    err = {"src_missing": (404, "el origen no existe"), "dst_exists": (409, "el destino ya existe"),
           "dst_parent_missing": (404, "el directorio destino no existe"),
           "into_itself": (400, "no se puede mover un directorio dentro de sí mismo"),
           "locked": (423, "hay archivos bloqueados por otra sesión")}.get(res)
    if err:
        raise HTTPException(*err)
    return {"ok": True}


# transferencia de archivos (rf2): init -> el cliente escribe los bloques directo a los datanodes por grpc -> complete (commit atómico) o abort

class InitUploadRequest(BaseModel):
    path: str
    size: int = Field(ge=0)
    block_size: Optional[int] = None


@app.post("/files/init")
def init_upload(req: InitUploadRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    path = access.norm(req.path)
    if path == "/":
        raise HTTPException(400, "path inválido")
    if storage.get_dir_owner(path) is not None:
        raise HTTPException(409, "ya existe un directorio con ese nombre")
    existing = storage.get_file(path)
    if existing:
        access.require_level(path, user, 2, owner=existing["owner"], what="este archivo")
        if storage.is_locked(path):
            raise HTTPException(423, "el archivo está bloqueado por otra sesión")
    else:
        access.require_dir(access.parent_of(path), user, 2)

    block_size = max(MIN_BLOCK_SIZE, min(req.block_size or DEFAULT_BLOCK_SIZE, MAX_BLOCK_SIZE))
    if -(-req.size // block_size) > MAX_BLOCKS_PER_FILE:
        raise HTTPException(400, f"el archivo necesitaría más de {MAX_BLOCKS_PER_FILE} bloques; usa un tamaño de bloque mayor")
    blocks = _plan_blocks(req.size, block_size)
    upload_id = uuid.uuid4().hex
    cluster.write("create_upload", upload_id=upload_id, path=path, owner=user, size=req.size,
                  block_size=block_size, blocks=blocks, now=time.time())

    return _upload_view(upload_id, storage.get_upload(upload_id))


def _upload_view(upload_id: str, up: dict) -> dict:
    alive = _alive_nodes()
    return {
        "upload_id": upload_id,
        "block_size": up["block_size"],
        "lease_ttl": min(UPLOAD_TTL, BLOCK_TOKEN_TTL),
        "blocks": [
            {
                "block_id": b["block_id"], "index": b["index"], "size": b["size"],
                "token": _tok(b["block_id"], "w"),
                "replicas": [{"node_id": n, "address": alive[n]["address"]} for n in b["nodes"] if n in alive],
            }
            for b in up["blocks"]
        ],
    }


class BlockResult(BaseModel):
    block_id: str
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    written: list[str]  # node_ids donde el cliente logró escribir el bloque


class CompleteUploadRequest(BaseModel):
    upload_id: str
    blocks: list[BlockResult]


def _require_owner(meta: dict, user: str):
    """los uploads y los handles son sesiones de quien los abrió"""
    if meta["owner"] != user:
        raise HTTPException(403, "esta sesión pertenece a otro usuario")


def _own_upload(upload_id: str, user: str) -> dict:
    up = storage.get_upload(upload_id)
    if up is None:
        raise HTTPException(404, "upload no existe o expiró")
    _require_owner(up, user)
    return up


class RenewUploadRequest(BaseModel):
    upload_id: str


@app.post("/files/renew")
def renew_upload(req: RenewUploadRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    up = _own_upload(req.upload_id, user)
    existing = storage.get_file(up["path"])
    if existing:
        access.require_level(up["path"], user, 2, owner=existing["owner"], what="este archivo")
    else:
        access.require_dir(access.parent_of(up["path"]), user, 2)
    up = cluster.write("refresh_upload", upload_id=req.upload_id, now=time.time())
    if up is None:
        raise HTTPException(404, "upload no existe o expiró")
    return _upload_view(req.upload_id, up)


@app.post("/files/complete")
def complete_upload(req: CompleteUploadRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    up = _own_upload(req.upload_id, user)
    existing = storage.get_file(up["path"])  # los permisos pudieron cambiar entre init y complete
    if existing:
        access.require_level(up["path"], user, 2, owner=existing["owner"], what="este archivo")
    else:
        access.require_dir(access.parent_of(up["path"]), user, 2)
    planned = {b["block_id"]: b for b in up["blocks"]}
    results = {r.block_id: r for r in req.blocks}
    if set(results) != set(planned):
        raise HTTPException(400, "el reporte de bloques no coincide con el plan del upload")

    final, degraded = [], 0
    for b in sorted(planned.values(), key=lambda x: x["index"]):
        r = results[b["block_id"]]
        written = [n for n in dict.fromkeys(r.written) if n in b["nodes"]]
        if len(written) < MIN_REPLICAS:
            cluster.write("delete_upload", upload_id=req.upload_id)
            _delete_blocks(up["blocks"])
            raise HTTPException(409, f"el bloque {b['index']} quedó con {len(written)} réplicas "
                                     f"(mínimo {MIN_REPLICAS}); upload cancelado")
        if len(written) < REPLICATION_FACTOR:
            degraded += 1
        final.append({**b, "nodes": written, "checksum": r.checksum})

    try:
        old_blocks = cluster.write("commit_upload", upload_id=req.upload_id, blocks=final, now=time.time())
    except storage.Locked:
        raise HTTPException(423, "el archivo está bloqueado por otra sesión")
    if old_blocks is None:
        raise HTTPException(404, "upload no existe o expiró")
    if old_blocks:
        _release_blocks(old_blocks)  # la versión anterior ya no se puede alcanzar
    if degraded:
        log.info("%s: %d bloques con menos réplicas que el factor; el monitor los completará", up["path"], degraded)
    return {"ok": True, "under_replicated_blocks": degraded}


class AbortUploadRequest(BaseModel):
    upload_id: str


@app.post("/files/abort")
def abort_upload(req: AbortUploadRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    _own_upload(req.upload_id, user)
    up = cluster.write("delete_upload", upload_id=req.upload_id)
    if up:
        _delete_blocks(up["blocks"])
    return {"ok": True}


# acceso a archivos (rf3): open, read, write, close y lock, con semántica de sesión tipo afs sobre bloques inmutables: open crea un handle con un snapshot de la versión actual y las lecturas siempre ven ese snapshot (más sus propias escrituras) aunque otros publiquen versiones nuevas, las escrituras se acumulan en el cliente y flush/close las publican como versión nueva con un commit atómico reescribiendo solo los bloques tocados, hay control optimista por versión (409 si el archivo cambió desde el open) más locks compartido/exclusivo (423 si chocan) obligatorios para escritores y los lectores nunca bloquean, handles y locks viven mientras el cliente mande keepalive (lease HANDLE_TTL) y los permisos se revisan en cada uso del handle, así que revocar una acl también corta las sesiones abiertas

def _own_handle(handle_id: str, user: str, write: bool = False) -> dict:
    with _handle_lease_lock:
        return _checked_handle(handle_id, user, write)


def _checked_handle(handle_id: str, user: str, write: bool = False) -> dict:
    """autorización y renovación, serializadas con la expiración del lease"""
    h = storage.get_handle(handle_id)
    if h is None:
        raise HTTPException(404, "handle no existe o expiró")
    _require_owner(h, user)
    HANDLE_SEEN[handle_id] = time.time()  # renueva el lease
    if write and not h["writable"]:
        raise HTTPException(403, "el handle se abrió en modo solo lectura")
    if h["base_version"] < 0:
        if write:
            raise HTTPException(404, "el archivo original de este handle fue eliminado")
        # es una lectura del archivo eliminado, no del que pueda ocupar ahora esa ruta, se conserva la autorización y el snapshot que tenía esa sesión
        return h
    f = storage.get_file(h["path"])
    if f is not None:
        access.require_level(h["path"], user, 2 if write else 1, owner=f["owner"], what="este archivo")
    return h


def _handle_view(h: dict) -> dict:
    alive = _alive_nodes()
    current = storage.file_block_nodes(h["path"])  # nodos actuales (el monitor pudo haberlos movido)
    blocks = []
    for b in sorted(h["blocks"], key=lambda x: x["index"]):
        nodes = current.get(b["block_id"], b["nodes"])
        addrs = [alive[n]["address"] for n in nodes if n in alive]
        random.shuffle(addrs)
        blocks.append({"block_id": b["block_id"], "index": b["index"], "size": b["size"],
                       "checksum": b["checksum"], "token": _tok(b["block_id"], "r"), "replicas": addrs})
    _check_replicas_visible(blocks)
    allocated = {a["block_id"]: {"replicas": [alive[n]["address"] for n in a["nodes"] if n in alive],
                                 "token": _tok(a["block_id"], "r")}
                 for a in h["allocated"]}
    return {"handle": h["handle_id"], "path": h["path"], "size": h["size"],
            "block_size": h["block_size"], "version": h["base_version"],
            "writable": h["writable"], "lease_ttl": min(HANDLE_TTL, BLOCK_TOKEN_TTL),
            "blocks": blocks, "allocated_replicas": allocated}


class OpenRequest(BaseModel):
    path: str
    mode: str = Field(pattern=r"^(r|r\+|w|w\+|a|a\+)$")
    block_size: Optional[int] = None  # solo se usa si el open crea el archivo


@app.post("/fs/open")
def fs_open(req: OpenRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    path = access.norm(req.path)
    writable = req.mode != "r"
    creates = req.mode in ("w", "w+", "a", "a+")
    if path == "/" or storage.get_dir_owner(path) is not None:
        raise HTTPException(409, "es un directorio")
    meta = storage.get_file(path)
    if meta is None:
        if not creates:
            raise HTTPException(404, "archivo no existe")
        access.require_dir(access.parent_of(path), user, 2)
        bs = max(MIN_BLOCK_SIZE, min(req.block_size or DEFAULT_BLOCK_SIZE, MAX_BLOCK_SIZE))
        cluster.write("create_empty_file", path=path, owner=user, block_size=bs, now=time.time())
        meta = storage.get_file(path)
    access.require_level(path, user, 2 if writable else 1, owner=meta["owner"], what="este archivo")
    h = cluster.write("open_handle", handle_id=uuid.uuid4().hex, path=path, owner=user,
                      writable=writable, now=time.time())
    if h is None:
        raise HTTPException(404, "archivo no existe")
    return _handle_view(h)


class HandleRequest(BaseModel):
    handle: str


@app.post("/fs/resolve")
def fs_resolve(req: HandleRequest, authorization: str = Header(None)):
    """direcciones actuales de las réplicas (los nodos pueden haber cambiado desde el open)"""
    user = access.current_user(authorization)
    return _handle_view(_own_handle(req.handle, user))


@app.post("/fs/refresh")
def fs_refresh(req: HandleRequest, authorization: str = Header(None)):
    """vuelve a tomar el snapshot de la versión actual (se usa después de conseguir un lock, para no trabajar sobre datos que otro publicó mientras esperaba)"""
    user = access.current_user(authorization)
    _own_handle(req.handle, user)
    try:
        return _handle_view(cluster.write("refresh_handle", handle_id=req.handle))
    except storage.Gone as e:
        raise HTTPException(404, f"{e} ya no existe")


@app.post("/fs/keepalive")
def fs_keepalive(req: HandleRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    _own_handle(req.handle, user)
    return {"ok": True, "lease_ttl": HANDLE_TTL}


class AllocRequest(BaseModel):
    handle: str
    sizes: list[int] = Field(min_length=1, max_length=1024)


@app.post("/fs/alloc")
def fs_alloc(req: AllocRequest, authorization: str = Header(None)):
    """reserva bloques nuevos (id + nodos) para que el cliente los escriba antes del commit"""
    user = access.current_user(authorization)
    h = _own_handle(req.handle, user, write=True)
    if any(sz < 0 or sz > h["block_size"] for sz in req.sizes):
        raise HTTPException(400, "tamaño de bloque inválido")
    blocks = _place_blocks(req.sizes)
    if not cluster.write("add_allocated", handle_id=req.handle, blocks=blocks):
        raise HTTPException(404, "handle no existe o expiró")
    alive = _alive_nodes()
    return {"blocks": [
        {"block_id": b["block_id"], "size": b["size"],
         "token": _tok(b["block_id"], "w"), "read_token": _tok(b["block_id"], "r"),
         "replicas": [{"node_id": n, "address": alive[n]["address"]} for n in b["nodes"] if n in alive]}
        for b in blocks
    ]}


class CommitBlock(BaseModel):
    block_id: str
    size: int = Field(ge=0)
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    written: Optional[list[str]] = None  # None = bloque sin cambios (ya estaba en el snapshot)


class CommitRequest(BaseModel):
    handle: str
    size: int = Field(ge=0)
    blocks: list[CommitBlock]


@app.post("/fs/commit")
def fs_commit(req: CommitRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    h = _own_handle(req.handle, user, write=True)
    bs = h["block_size"]
    if len(req.blocks) > MAX_BLOCKS_PER_FILE or len(req.blocks) != -(-req.size // bs):
        raise HTTPException(400, "la cantidad de bloques no corresponde al tamaño (o excede el máximo por archivo)")
    if len({b.block_id for b in req.blocks}) != len(req.blocks):
        raise HTTPException(400, "bloques repetidos")
    snapshot = {b["block_id"]: b for b in h["blocks"]}
    allocated = {b["block_id"]: b for b in h["allocated"]}

    final, degraded = [], 0
    for i, cb in enumerate(req.blocks):
        expected = min(bs, req.size - i * bs)
        if cb.size != expected:
            raise HTTPException(400, f"el bloque {i} debe medir {expected} bytes")
        if cb.written is None:
            base = snapshot.get(cb.block_id)
            if base is None or base["size"] != cb.size or base["checksum"] != cb.checksum:
                raise HTTPException(400, f"el bloque {i} no coincide con el snapshot")
            nodes = None
        else:
            planned = allocated.get(cb.block_id)
            if planned is None:
                raise HTTPException(400, f"el bloque {i} no fue asignado a este handle")
            nodes = [n for n in dict.fromkeys(cb.written) if n in planned["nodes"]]
            if len(nodes) < MIN_REPLICAS:
                raise HTTPException(409, f"el bloque {i} quedó con {len(nodes)} réplicas (mínimo {MIN_REPLICAS})")
            degraded += len(nodes) < REPLICATION_FACTOR
        final.append({"block_id": cb.block_id, "index": i, "size": cb.size,
                      "nodes": nodes, "checksum": cb.checksum})
    try:
        old_blocks, allocated_before, h2 = cluster.write("commit_handle", handle_id=req.handle, size=req.size,
                                                         blocks=final, now=time.time())
    except storage.Gone as e:
        raise HTTPException(404, f"{e} ya no existe")
    except storage.Conflict as e:
        raise HTTPException(409, f"conflicto: el archivo cambió desde que se abrió ({e})")
    except storage.Locked:
        raise HTTPException(423, "el archivo está bloqueado por otra sesión")
    kept = {b["block_id"] for b in h2["blocks"]}
    _release_blocks([b for b in old_blocks + allocated_before if b["block_id"] not in kept])
    view = _handle_view(h2)
    view["under_replicated_blocks"] = degraded
    return view


class LockRequest(BaseModel):
    handle: str
    mode: str = Field(pattern=r"^(shared|exclusive|none)$")


@app.post("/fs/lock")
def fs_lock(req: LockRequest, authorization: str = Header(None)):
    """consigue, convierte o suelta ('none') el lock del archivo, no bloquea y responde 423 si choca"""
    user = access.current_user(authorization)
    h = _own_handle(req.handle, user, write=(req.mode == "exclusive"))
    if req.mode == "none":
        cluster.write("release_lock", path=h["path"], handle_id=req.handle)
    elif not cluster.write("acquire_lock", path=h["path"], handle_id=req.handle, mode=req.mode):
        raise HTTPException(423, "el archivo está bloqueado por otra sesión")
    return {"ok": True}


@app.post("/fs/close")
def fs_close(req: HandleRequest, authorization: str = Header(None)):
    user = access.current_user(authorization)
    h = storage.get_handle(req.handle)
    if h is None:
        raise HTTPException(404, "handle no existe o expiró")
    _require_owner(h, user)  # cerrar siempre se puede, aunque ya no haya permisos sobre el archivo
    _close_handle(req.handle)
    return {"ok": True}


@app.get("/fs/stat")
def fs_stat(path: str, authorization: str = Header(None)):
    user = access.current_user(authorization)
    path = access.norm(path)
    meta = storage.get_file(path)
    if meta is None:
        if storage.get_dir_owner(path) is None:
            raise HTTPException(404, "no existe")
        access.require_dir(path, user, 1)
        return {"path": path, "type": "dir", "owner": storage.get_dir_owner(path)}
    access.require_level(path, user, 1, owner=meta["owner"], what="este archivo")
    alive = _alive_nodes()
    live = [sum(n in alive for n in b["nodes"]) for b in meta["blocks"]]
    return {"path": path, "type": "file", "owner": meta["owner"], "size": meta["size"], "mtime": meta["created_at"],
            "block_size": meta["block_size"], "version": meta["version"], "blocks": len(meta["blocks"]),
            "min_live_replicas": min(live) if live else None,
            "locks": [l["mode"] for l in storage.locks_for(path)],
            "acl": storage.acl_for(path) if access.level_of(path, user, meta["owner"]) >= access.OWNER else None}


@app.get("/files/{path:path}")
def get_file_metadata(path: str, authorization: str = Header(None)):
    user = access.current_user(authorization)
    full_path = access.norm("/" + path)
    meta = storage.get_file(full_path)
    if not meta:
        raise HTTPException(404, "archivo no existe")
    access.require_level(full_path, user, 1, owner=meta["owner"], what="este archivo")
    alive = _alive_nodes()
    blocks = []
    for b in sorted(meta["blocks"], key=lambda x: x["index"]):
        addrs = [alive[n]["address"] for n in b["nodes"] if n in alive]
        random.shuffle(addrs)  # reparte la carga de lectura entre las réplicas
        blocks.append({"block_id": b["block_id"], "index": b["index"], "size": b["size"],
                       "checksum": b["checksum"], "token": _tok(b["block_id"], "r"), "replicas": addrs})
    _check_replicas_visible(blocks)
    return {"path": full_path, "size": meta["size"], "block_size": meta["block_size"], "blocks": blocks}


@app.get("/admin/cluster")
def admin_cluster(authorization: str = Header(None)):
    """estado del cluster para operadores (solo el usuario 'admin'): nodos, réplicas y raft"""
    if access.current_user(authorization) != "admin":
        raise HTTPException(403, "solo el usuario admin puede ver el estado del cluster")
    now = time.time()
    holders = _alive_nodes(REREPLICATE_AFTER)
    files = storage.list_files()
    per_node = {n: 0 for n in DATANODES}
    under = lost = blocks = 0
    for meta in files.values():
        for b in meta["blocks"]:
            blocks += 1
            for n in b["nodes"]:
                per_node[n] = per_node.get(n, 0) + 1
            live = sum(n in holders for n in b["nodes"])
            under += 0 < live < REPLICATION_FACTOR
            lost += live == 0
    return {
        "raft": cluster.status(),
        "replication_factor": REPLICATION_FACTOR,
        "files": len(files), "blocks": blocks, "under_replicated_blocks": under, "lost_blocks": lost,
        "datanodes": [{"node_id": n, "alive": now - i["last_seen"] <= HEARTBEAT_TIMEOUT,
                       "seen_ago": round(now - i["last_seen"], 1), "used_bytes": i["used_bytes"],
                       "blocks": per_node.get(n, 0)} for n, i in sorted(DATANODES.items())],
        "security": {"tls": TLS, "dev_secret": KEYS.insecure},
    }


@app.get("/health")
def health():
    return {"ok": True, "datanodes_alivos": len(_alive_nodes()), "raft": cluster.status(),
            "security": {"tls": TLS, "dev_secret": KEYS.insecure}}


@app.get("/raft/status")
def raft_status():
    return cluster.status()
