"""data node: guarda los bloques en el disco local y los expone por grpc; tiene dos puertos, el público (tls) solo sirve WriteBlock/ReadBlock a los clientes y el interno (mtls, pide certificado de cliente firmado por la ca del cluster) atiende al control node y a otros datanodes (DeleteBlock, ReplicateBlock, ReadBlock); toda operación sobre un bloque exige un token firmado por el control node (metadato x-dfsha-token) y los bloques se guardan cifrados con aes-256-gcm usando el id del bloque como dato asociado, así no se pueden copiar con otro nombre ni alterar sin que se note; formato en disco (<block_id>.blk): DFS2 | nonce de 12 bytes | aes-gcm(sha256 en hex + salto de línea + datos), se escribe a un .tmp y se publica con rename atómico para que un corte nunca deje un bloque a medias; además del heartbeat, cada BLOCK_REPORT_INTERVAL reporta sus bloques al líder, que responde con los huérfanos para borrarlos"""
import os
import re
import time
import hashlib
import logging
import threading
import tempfile
import uuid
from concurrent import futures
from concurrent.futures import ThreadPoolExecutor

import grpc
import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import dfsha_pb2
import dfsha_pb2_grpc
import dfsha_security as sec

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("datanode")

NODE_ID = os.environ.get("NODE_ID", "datanode-unknown")
NODE_ADDR = os.environ.get("NODE_ADDR", "localhost:6000")  # host:puerto público (clientes, fuera de docker)
INTERNAL_ADDR = os.environ.get("INTERNAL_ADDR", "localhost:6100")  # host:puerto interno (control node y otros datanodes)
DATA_DIR = os.environ.get("DATA_DIR", "/data")
CONTROL_NODE_URLS = [u.strip() for u in os.environ.get(
    "CONTROL_NODE_URLS", os.environ.get("CONTROL_NODE_URL", "http://control1:8000")).split(",") if u.strip()]
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "5"))
BLOCK_REPORT_INTERVAL = int(os.environ.get("BLOCK_REPORT_INTERVAL", "30"))
ORPHAN_MIN_AGE = int(os.environ.get("ORPHAN_MIN_AGE", "60"))  # un bloque más nuevo que esto nunca se reporta como posible huérfano
SCRUB_INTERVAL = int(os.environ.get("SCRUB_INTERVAL", "3600"))  # cada cuánto se verifican todos los bloques (0 = nunca)
SCRUB_MB_PER_SEC = float(os.environ.get("SCRUB_MB_PER_SEC", "20"))
GRPC_PORT = os.environ.get("GRPC_PORT", "6000")
INTERNAL_GRPC_PORT = os.environ.get("INTERNAL_GRPC_PORT", "6100")
MAX_MSG = 64 * 1024 * 1024
GRPC_OPTS = [("grpc.max_send_message_length", MAX_MSG), ("grpc.max_receive_message_length", MAX_MSG),
             ("grpc.initial_reconnect_backoff_ms", 500), ("grpc.max_reconnect_backoff_ms", 3000),
             ("grpc.dns_min_time_between_resolutions_ms", 1000)]

TLS_CERT, TLS_KEY, TLS_CA = (os.environ.get(k) for k in ("TLS_CERT", "TLS_KEY", "TLS_CA"))
TLS = bool(TLS_CERT and TLS_KEY and TLS_CA)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


KEYS = sec.Keys(os.environ.get("CLUSTER_SECRET"))
DISK_KEY = bytes.fromhex(os.environ["DATA_KEY"]) if os.environ.get("DATA_KEY") else KEYS.disk
if len(DISK_KEY) != 32:
    raise SystemExit("DATA_KEY debe ser una clave AES-256 en hexadecimal (64 caracteres)")
AEAD = AESGCM(DISK_KEY)
MAGIC = b"DFS2"

BLOCK_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# bloquea por id sin una tabla de locks que crezca con la cantidad de bloques
_block_locks = [threading.RLock() for _ in range(256)]
_inventory_lock = threading.RLock()
INVENTORY_ID = uuid.uuid4().hex  # identidad de este arranque, las generaciones no se reutilizan

os.makedirs(DATA_DIR, exist_ok=True)


def _block_path(block_id: str) -> str:
    return os.path.join(DATA_DIR, block_id + ".blk")


def _valid_id(block_id: str) -> bool:
    return bool(BLOCK_ID_RE.match(block_id))


def _block_lock(block_id: str):
    return _block_locks[int(block_id[:2], 16)]


def _store_block(block_id: str, data: bytes, checksum: str, *, repair: bool = False):
    """publica un bloque completo (un reintento idéntico no cambia nada), solo la replicación interna autenticada puede reparar una copia que no coincide con el checksum de los metadatos, y un token público de escritura nunca puede reemplazar un id ya publicado ni siquiera si está corrupto"""
    if hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("checksum mismatch")
    path = _block_path(block_id)
    with _block_lock(block_id):
        exists = False
        try:
            previous, previous_checksum = _load_block(block_id)
            exists = True
            if previous_checksum == checksum and previous == data:
                return
            if not repair:
                raise FileExistsError("bloque inmutable: el id ya contiene otros datos")
        except FileNotFoundError:
            pass
        except ValueError:
            if not repair:
                raise ValueError("bloque corrupto: requiere reparación interna")
            exists = True

        nonce = os.urandom(12)
        sealed = AEAD.encrypt(nonce, checksum.encode() + b"\n" + data, block_id.encode())
        fd, tmp = tempfile.mkstemp(prefix=block_id + ".", suffix=".tmp", dir=DATA_DIR)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(MAGIC + nonce + sealed)
                f.flush()
                os.fsync(f.fileno())
            with _inventory_lock:
                if repair and exists:
                    os.replace(tmp, path)
                else:
                    # publicación atómica sin sobrescribir, incluso si hay otro proceso
                    try:
                        if os.name == "nt":
                            os.rename(tmp, path)  # windows no deja renombrar sobre un destino que ya existe
                        else:
                            os.link(tmp, path)
                    except FileExistsError:
                        previous, previous_checksum = _load_block(block_id)
                        if previous_checksum != checksum or previous != data:
                            raise FileExistsError("bloque inmutable: el id ya contiene otros datos")
            if repair:
                with _corrupt_lock:
                    _corrupt_report.discard(block_id)
        finally:
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass


_corrupt_report: set[str] = set()  # bloques en cuarentena que el líder todavía no confirmó
_corrupt_lock = threading.Lock()


def _quarantine(block_id: str, reason: str):
    """aparta un bloque corrupto (<id>.corrupt) para que no se sirva ni cuente como réplica y lo reporta en los siguientes heartbeats hasta que el líder lo confirme (entonces repone la réplica en otro nodo)"""
    path = _block_path(block_id)
    with _block_lock(block_id):
        with _inventory_lock:
            try:
                os.replace(path, path[:-4] + ".corrupt")
            except FileNotFoundError:
                return
        with _corrupt_lock:
            _corrupt_report.add(block_id)
    log.error("Bloque %s puesto en cuarentena: %s", block_id, reason)


def scrub_once() -> int:
    """verifica todos los bloques (descifra y compara el checksum) y manda los corruptos a cuarentena, devuelve cuántos encontró, va a ritmo limitado (SCRUB_MB_PER_SEC) para no competir con el tráfico"""
    bad = 0
    with os.scandir(DATA_DIR) as it:
        names = [e.name for e in it if e.name.endswith(".blk")]
    for name in names:
        block_id = name[:-4]
        if not _valid_id(block_id):
            continue
        with _block_lock(block_id):
            try:
                data, _ = _load_block(block_id)
            except FileNotFoundError:
                continue
            except ValueError as e:
                _quarantine(block_id, str(e))
                bad += 1
                continue
        if SCRUB_MB_PER_SEC > 0:
            time.sleep(len(data) / (SCRUB_MB_PER_SEC * 1024 * 1024))
    return bad


def scrub_loop():
    while SCRUB_INTERVAL > 0:
        time.sleep(SCRUB_INTERVAL)
        try:
            n = scrub_once()
            log.info("scrub completado: %d bloques corruptos", n)
        except Exception:  # noqa: BLE001
            log.exception("error en el scrub")


def _load_block(block_id: str):
    """devuelve (data, checksum) o lanza FileNotFoundError / ValueError si está corrupto o alterado"""
    with open(_block_path(block_id), "rb") as f:
        raw = f.read()
    if raw[:4] != MAGIC or len(raw) < 4 + 12 + 16:
        raise ValueError("formato de bloque desconocido (bloque corrupto)")
    try:
        plain = AEAD.decrypt(raw[4:16], raw[16:], block_id.encode())
    except InvalidTag:
        raise ValueError("el bloque no se pudo descifrar (corrupto o alterado)")
    stored, data = plain[:64].decode(errors="replace"), plain[65:]
    if plain[64:65] != b"\n" or hashlib.sha256(data).hexdigest() != stored:
        raise ValueError("checksum en disco no coincide (bloque corrupto)")
    return data, stored


# autorización

def _metadata(context) -> dict:
    return {k: v for k, v in context.invocation_metadata()}


def _authorize(context, block_id: str, ops: str):
    """pide un token de acceso firmado por el control node para este bloque y esta operación"""
    if not _valid_id(block_id):
        context.abort(grpc.StatusCode.INVALID_ARGUMENT, "block_id inválido")
    if not sec.verify_block_token(KEYS, _metadata(context).get("x-dfsha-token"), block_id, ops):
        context.abort(grpc.StatusCode.PERMISSION_DENIED,
                      "token de acceso al bloque ausente, inválido, vencido o de otra operación")


def _check_identity(context):
    """las llamadas internas dicen con qué nodo creen hablar (x-dfsha-expect-node), si el dns o la ip apunta a otro datanode (por ejemplo una ip reasignada al reiniciar un contenedor) se rechaza en vez de operar sobre el nodo equivocado"""
    expect = _metadata(context).get("x-dfsha-expect-node")
    if expect and expect != NODE_ID:
        context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"soy {NODE_ID}, no {expect}")


def _peer_channel(address: str) -> grpc.Channel:
    """canal hacia otro datanode (puerto interno, mtls)"""
    if TLS:
        creds = grpc.ssl_channel_credentials(root_certificates=_read(TLS_CA),
                                             private_key=_read(TLS_KEY), certificate_chain=_read(TLS_CERT))
        return grpc.secure_channel(address, creds, options=GRPC_OPTS)
    return grpc.insecure_channel(address, options=GRPC_OPTS)


# operaciones

def _do_write(request, context):
    _authorize(context, request.block_id, "w")
    try:
        checksum = hashlib.sha256(request.data).hexdigest()
        if request.checksum and request.checksum != checksum:
            return dfsha_pb2.Ack(success=False, message="checksum mismatch")
        _store_block(request.block_id, request.data, checksum)
        log.info("Bloque %s escrito (%d bytes)", request.block_id, len(request.data))
        return dfsha_pb2.Ack(success=True, message=checksum)
    except Exception as e:  # noqa: BLE001
        log.exception("Error escribiendo bloque %s", request.block_id)
        return dfsha_pb2.Ack(success=False, message=str(e))


def _do_read(request, context):
    _authorize(context, request.block_id, "r")
    with _block_lock(request.block_id):
        try:
            data, checksum = _load_block(request.block_id)
        except FileNotFoundError:
            context.abort(grpc.StatusCode.NOT_FOUND, f"bloque {request.block_id} no existe en este nodo")
        except ValueError as e:
            _quarantine(request.block_id, str(e))
            context.abort(grpc.StatusCode.DATA_LOSS, str(e))
    return dfsha_pb2.Block(block_id=request.block_id, data=data, checksum=checksum)


def _do_delete(request, context):
    _authorize(context, request.block_id, "d")
    _remove_block(request.block_id)
    return dfsha_pb2.Ack(success=True, message="deleted")


def _remove_block(block_id: str):
    with _block_lock(block_id), _inventory_lock:
        try:
            os.remove(_block_path(block_id))
            log.info("Bloque %s borrado", block_id)
        except FileNotFoundError:
            pass


def _do_replicate(request, context):
    """datanode <-> datanode: este nodo jala el bloque desde source_address"""
    _authorize(context, request.block_id, "x")
    with _block_lock(request.block_id):
        try:
            _, existing_checksum = _load_block(request.block_id)
            if request.checksum and existing_checksum == request.checksum:
                return dfsha_pb2.Ack(success=True, message="ya existía")
        except (FileNotFoundError, ValueError):
            pass
    meta = [("x-dfsha-token", request.source_token)]
    if request.source_node:
        meta.append(("x-dfsha-expect-node", request.source_node))
    try:
        with _peer_channel(request.source_address) as channel:
            blk = dfsha_pb2_grpc.DataNodeStub(channel).ReadBlock(
                dfsha_pb2.BlockId(block_id=request.block_id), timeout=60, metadata=meta)
    except grpc.RpcError as e:
        return dfsha_pb2.Ack(success=False, message=f"origen {request.source_address}: {e.details()}")
    checksum = hashlib.sha256(blk.data).hexdigest()
    if not request.checksum or request.checksum != checksum:
        return dfsha_pb2.Ack(success=False, message="checksum del origen no coincide con los metadatos")
    _store_block(request.block_id, blk.data, checksum, repair=True)
    log.info("Bloque %s replicado desde %s (%d bytes)", request.block_id, request.source_address, len(blk.data))
    return dfsha_pb2.Ack(success=True, message=checksum)


def _deny(context, what: str):
    context.abort(grpc.StatusCode.PERMISSION_DENIED, f"{what} no está disponible en este puerto")


class PublicServicer(dfsha_pb2_grpc.DataNodeServicer):
    """puerto de clientes: solo leer y escribir bloques con un token del control node"""

    def WriteBlock(self, request, context):
        return _do_write(request, context)

    def ReadBlock(self, request, context):
        return _do_read(request, context)

    def DeleteBlock(self, request, context):
        _deny(context, "DeleteBlock")

    def ReplicateBlock(self, request, context):
        _deny(context, "ReplicateBlock")

    def Ping(self, request, context):
        _deny(context, "Ping")


class InternalServicer(dfsha_pb2_grpc.DataNodeServicer):
    """puerto interno (mtls): control node y otros datanodes"""

    def WriteBlock(self, request, context):
        _deny(context, "WriteBlock")

    def ReadBlock(self, request, context):
        _check_identity(context)
        return _do_read(request, context)

    def DeleteBlock(self, request, context):
        _check_identity(context)
        return _do_delete(request, context)

    def ReplicateBlock(self, request, context):
        _check_identity(context)
        return _do_replicate(request, context)

    def Ping(self, request, context):
        _check_identity(context)
        return dfsha_pb2.Ack(success=True, message="pong")


# heartbeat

def _scan_blocks():
    """foto de los nombres: bytes, candidatos viejos para el gc y el inventario completo, publicar, borrar y poner en cuarentena usan el mismo lock así que un bloque reciente nunca desaparece del inventario por el filtro de edad del gc"""
    used, old_ids, all_ids, now = 0, [], [], time.time()
    with _inventory_lock, os.scandir(DATA_DIR) as it:
        for e in it:
            if not e.name.endswith(".blk") or not _valid_id(e.name[:-4]):
                continue
            try:
                st = e.stat()
            except FileNotFoundError:  # alguien pudo haber borrado el archivo por fuera
                continue
            all_ids.append(e.name[:-4])
            used += st.st_size
            if now - st.st_mtime >= ORPHAN_MIN_AGE:
                old_ids.append(e.name[:-4])
    return used, sorted(old_ids), sorted(all_ids)


def _heartbeat_payloads(pending: dict, generation: int, report_due: bool):
    """responde solo los desafíos recibidos antes de tomar este inventario: cada control node manda inventory_request y guarda las réplicas que esperaba en ese momento, y solo puede declarar ausentes esas al recibir el eco del desafío con inventory_blocks, así no confunde una escritura nueva con una pérdida ni compara relojes de máquinas distintas, el id de arranque y la generación sirven para descartar respuestas viejas o repetidas, y block_ids sigue significando candidatos viejos para el gc"""
    used, old_ids, all_ids = _scan_blocks()
    if pending:
        generation += 1
    base = {"node_id": NODE_ID, "address": NODE_ADDR, "internal_address": INTERNAL_ADDR,
            "used_bytes": used, "inventory_id": INVENTORY_ID, "inventory_generation": generation}
    if report_due:
        base["block_ids"] = old_ids
    with _corrupt_lock:
        if _corrupt_report:
            base["corrupt_blocks"] = sorted(_corrupt_report)
    payloads = {}
    for url in CONTROL_NODE_URLS:
        payloads[url] = dict(base)
        if pending.get(url):
            payloads[url].update(inventory_request=pending[url], inventory_blocks=all_ids)
    return payloads, generation


def _beat(url: str, payload: dict):
    try:
        r = requests.post(f"{url}/datanodes/register", json=payload, timeout=3,
                          headers={"X-DFSha-Node-Token": sec.make_node_token(KEYS, NODE_ID)},
                          verify=TLS_CA if TLS else True)
        r.raise_for_status()
        return r.json()
    except Exception as e:  # noqa: BLE001
        log.warning("No se pudo hacer heartbeat a %s: %s", url, e)
        return None


def heartbeat_loop():
    """se registra cada cierto tiempo en todos los control nodes (cada uno guarda su registro de nodos vivos, así después de un failover el líder nuevo ya está al día), solo se obedecen las órdenes de borrado del líder y si algún control node está caído se reintenta sin tumbar el datanode"""
    last_report = 0.0
    pending, generation = {}, 0
    pool = ThreadPoolExecutor(max_workers=max(1, len(CONTROL_NODE_URLS)))
    while True:
        try:
            report_due = time.time() - last_report >= BLOCK_REPORT_INTERVAL
            payloads, generation = _heartbeat_payloads(pending, generation, report_due)
            responses = list(pool.map(lambda u: _beat(u, payloads[u]), CONTROL_NODE_URLS))
            for url, response in zip(CONTROL_NODE_URLS, responses):
                if response is None:
                    continue  # reintenta el mismo desafío en el siguiente heartbeat
                pending.pop(url, None)
                challenge = response.get("inventory_request")
                if isinstance(challenge, str) and challenge:
                    pending[url] = challenge
            leader = next((r for r in responses if r and r.get("leader")), None)
            if leader:
                with _corrupt_lock:
                    _corrupt_report.difference_update(leader.get("corrupt_ack", []))
            if report_due and leader:
                last_report = time.time()
                for block_id in leader.get("delete_blocks", []):
                    if _valid_id(block_id):
                        log.info("Borrando bloque huérfano %s", block_id)
                        _remove_block(block_id)
        except Exception:  # noqa: BLE001
            log.exception("error en el heartbeat")
        time.sleep(HEARTBEAT_INTERVAL)


def serve():
    for name in os.listdir(DATA_DIR):  # restos de escrituras interrumpidas
        if name.endswith(".tmp"):
            os.remove(os.path.join(DATA_DIR, name))
    if KEYS.insecure:
        log.warning("CLUSTER_SECRET no está definido: se usa una clave de desarrollo INSEGURA")

    public = grpc.server(futures.ThreadPoolExecutor(max_workers=16), options=GRPC_OPTS)
    dfsha_pb2_grpc.add_DataNodeServicer_to_server(PublicServicer(), public)
    internal = grpc.server(futures.ThreadPoolExecutor(max_workers=8), options=GRPC_OPTS)
    dfsha_pb2_grpc.add_DataNodeServicer_to_server(InternalServicer(), internal)
    if TLS:
        key, cert, ca = _read(TLS_KEY), _read(TLS_CERT), _read(TLS_CA)
        public.add_secure_port(f"[::]:{GRPC_PORT}", grpc.ssl_server_credentials([(key, cert)]))
        internal.add_secure_port(f"[::]:{INTERNAL_GRPC_PORT}", grpc.ssl_server_credentials(
            [(key, cert)], root_certificates=ca, require_client_auth=True))
    else:
        log.warning("TLS desactivado (faltan TLS_CERT/TLS_KEY/TLS_CA): el tráfico va en claro")
        public.add_insecure_port(f"[::]:{GRPC_PORT}")
        internal.add_insecure_port(f"[::]:{INTERNAL_GRPC_PORT}")
    public.start()
    internal.start()
    log.info("DataNode %s: público :%s (%s) / interno :%s (%s) / TLS=%s",
             NODE_ID, GRPC_PORT, NODE_ADDR, INTERNAL_GRPC_PORT, INTERNAL_ADDR, TLS)

    threading.Thread(target=heartbeat_loop, daemon=True).start()
    threading.Thread(target=scrub_loop, daemon=True).start()
    public.wait_for_termination()


if __name__ == "__main__":
    serve()
