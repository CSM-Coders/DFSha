"""librería cliente de dfsha: rest contra el control node (metadatos) y grpc directo contra los datanodes (datos), el cli (cli.py) es una capa fina sobre esta clase"""
import os
import json
import time
import base64
import hashlib
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

import grpc
import requests

import dfsha_pb2
import dfsha_pb2_grpc

MAX_MSG = 64 * 1024 * 1024
GRPC_OPTS = [("grpc.max_send_message_length", MAX_MSG), ("grpc.max_receive_message_length", MAX_MSG),
             ("grpc.initial_reconnect_backoff_ms", 300), ("grpc.max_reconnect_backoff_ms", 3000)]
PARALLEL_BLOCKS = 4
DEFAULT_URLS = os.environ.get("CONTROL_NODE_URL", "https://localhost:8001,https://localhost:8002,https://localhost:8003")
_REPO_CA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certs", "ca.crt")


def default_ca() -> Optional[str]:
    """ca del cluster: DFSHA_CA_CERT, o certs/ca.crt si se usa el repo tal cual"""
    ca = os.environ.get("DFSHA_CA_CERT")
    if ca:
        return ca
    return _REPO_CA if os.path.exists(_REPO_CA) else None


_channels: dict = {}
_channels_lock = threading.Lock()


def _address_map() -> dict:
    """DFSHA_ADDRESS_MAP="localhost:6001=datanode1:6000,..." reescribe las direcciones de datanodes que anuncia el cluster (sirve cuando el cliente no puede llegar a ellas tal cual: dentro de la red de docker, detrás de un proxy o con nat)"""
    out = {}
    for pair in os.environ.get("DFSHA_ADDRESS_MAP", "").split(","):
        if "=" in pair:
            a, b = pair.split("=", 1)
            out[a.strip()] = b.strip()
    return out


def grpc_channel(address: str, ca: Optional[str]) -> grpc.Channel:
    """canal (guardado y seguro entre hilos) hacia el puerto público de un datanode: tls si hay ca"""
    address = _address_map().get(address, address)
    key = (address, ca)
    with _channels_lock:
        ch = _channels.get(key)
        if ch is None:
            if ca:
                with open(ca, "rb") as f:
                    ch = grpc.secure_channel(address, grpc.ssl_channel_credentials(root_certificates=f.read()),
                                             options=GRPC_OPTS)
            else:
                ch = grpc.insecure_channel(address, options=GRPC_OPTS)
            _channels[key] = ch
    return ch
RETRY_SECONDS = float(os.environ.get("DFSHA_RETRY_SECONDS", "25"))  # cuánto esperar por una elección de líder o un nodo caído


class DFShaError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class DFShaClient:
    def __init__(self, base_url=DEFAULT_URLS, token: Optional[str] = None, ca_cert: Optional[str] = None):
        """base_url: un control node o varios (lista o texto separado por comas), cualquiera sirve porque los seguidores reenvían al líder y si uno cae se prueba el siguiente; ca_cert: ca del cluster para verificar tls (por defecto DFSHA_CA_CERT o certs/ca.crt)"""
        urls = base_url if isinstance(base_url, (list, tuple)) else str(base_url).split(",")
        self._urls = [u.strip().rstrip("/") for u in urls if u.strip()]
        self.base_url = self._urls[0]
        self._cur = 0
        self.token = token
        self.ca = ca_cert or default_ca()
        self._http = requests.Session()
        self._http.verify = self.ca or True

    # rest

    def _request(self, method: str, path: str, **kw):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        deadline = time.time() + RETRY_SECONDS
        last = "sin respuesta"
        while True:
            n = len(self._urls)
            for i in range(n):
                idx = (self._cur + i) % n
                url = self._urls[idx]
                try:
                    r = self._http.request(method, f"{url}{path}", headers=headers, timeout=30, **kw)
                except requests.exceptions.SSLError as e:
                    raise DFShaError(f"fallo TLS con {url}: {e}. ¿Apunta DFSHA_CA_CERT a la CA del cluster (certs/ca.crt)?") from e
                except (requests.ConnectionError, requests.ConnectTimeout):
                    last = f"{url}: no se pudo conectar"
                    continue
                except requests.RequestException as e:
                    # por ejemplo timeout de lectura: la operación pudo ejecutarse, no se reintenta a ciegas
                    raise DFShaError(f"error de comunicación con {url}: {e}") from e
                if r.status_code == 503:  # elección de líder en curso, sin quórum, etc.
                    last = f"{url}: 503 {r.text[:120]}"
                    continue
                self._cur = idx
                if not r.ok:
                    try:
                        detail = r.json().get("detail", r.text)
                    except ValueError:
                        detail = r.text
                    raise DFShaError(f"{r.status_code}: {detail}", status=r.status_code)
                return r.json()
            if time.time() >= deadline:
                raise DFShaError(f"503: el cluster no responde ({last})", status=503)
            time.sleep(0.5)

    @property
    def username(self) -> str:
        """usuario de la sesión actual (solo lee el token, quien lo valida es el servidor)"""
        try:
            payload = self.token.split(".")[0]
            return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["u"]
        except Exception:  # noqa: BLE001
            return ""

    def register(self, user: str, password: str):
        self._request("POST", "/auth/register", json={"username": user, "password": password})

    def login(self, user: str, password: str, otp: Optional[str] = None) -> str:
        body = {"username": user, "password": password}
        if otp:
            body["otp"] = otp
        self.token = self._request("POST", "/auth/login", json=body)["token"]
        return self.token

    def login_apikey(self, key: str) -> str:
        self.token = self._request("POST", "/auth/apikey-login", json={"key": key})["token"]
        return self.token

    def logout_all(self):
        """revoca todas las sesiones del usuario (incluida esta)"""
        self._request("POST", "/auth/logout-all")

    def change_password(self, old: str, new: str) -> str:
        self.token = self._request("POST", "/auth/password", json={"old_password": old, "new_password": new})["token"]
        return self.token

    # 2fa, api keys, grupos y permisos

    def totp_setup(self) -> dict:
        return self._request("POST", "/auth/2fa/setup")

    def totp_enable(self, code: str):
        self._request("POST", "/auth/2fa/enable", json={"code": code})

    def totp_disable(self, password: str, code: Optional[str] = None):
        self._request("POST", "/auth/2fa/disable", json={"password": password, "code": code})

    def apikey_create(self, label: str = "") -> dict:
        return self._request("POST", "/auth/apikeys", json={"label": label})

    def apikey_list(self) -> list:
        return self._request("GET", "/auth/apikeys")["keys"]

    def apikey_revoke(self, key_id: str):
        self._request("POST", "/auth/apikeys/revoke", json={"key_id": key_id})

    def group_create(self, name: str):
        self._request("POST", "/groups", json={"name": name})

    def group_list(self) -> list:
        return self._request("GET", "/groups")["groups"]

    def group_add(self, name: str, username: str) -> dict:
        return self._request("POST", f"/groups/{name}/members", json={"username": username, "action": "add"})

    def group_remove(self, name: str, username: str) -> dict:
        return self._request("POST", f"/groups/{name}/members", json={"username": username, "action": "remove"})

    def group_delete(self, name: str):
        self._request("POST", f"/groups/{name}/delete")

    def share(self, path: str, principal: str, perm: str):
        """da permiso 'r' o 'rw' (o 'none' para quitarlo) a 'user:NOMBRE' o 'group:NOMBRE' sobre un archivo o directorio"""
        self._request("POST", "/acl/set", json={"path": path, "principal": principal, "perm": perm})

    def acl(self, path: str) -> list:
        return self._request("GET", "/acl", params={"path": path})["acl"]

    def cluster_status(self) -> dict:
        """estado del cluster (solo el usuario admin): nodos, réplicas y raft"""
        return self._request("GET", "/admin/cluster")

    def shared(self) -> list:
        """lo que otros compartieron conmigo (directo o por mis grupos)"""
        return self._request("GET", "/acl/shared")["shared"]

    def mkdir(self, path: str):
        self._request("POST", "/mkdir", json={"path": path})

    def rmdir(self, path: str):
        self._request("POST", "/rmdir", json={"path": path})

    def ls(self, path: str = "/") -> dict:
        return self._request("GET", "/ls", params={"path": path})

    def rm(self, path: str):
        self._request("POST", "/rm", json={"path": path})

    def stat(self, path: str) -> dict:
        return self._request("GET", "/fs/stat", params={"path": path})

    def mv(self, src: str, dst: str):
        """mueve o renombra un archivo o directorio (atómico, conserva permisos y sesiones abiertas)"""
        self._request("POST", "/mv", json={"src": src, "dst": dst})

    def kind(self, path: str) -> Optional[str]:
        """'file', 'dir' o None si no existe"""
        try:
            return self.stat(path)["type"]
        except DFShaError as e:
            if e.status == 404:
                return None
            raise

    def mkdir_p(self, path: str):
        """crea el directorio y los que falten por encima (como mkdir -p)"""
        built = ""
        for part in [p for p in path.split("/") if p]:
            built += "/" + part
            try:
                self.mkdir(built)
            except DFShaError as e:
                if e.status not in (403, 409) or self.kind(built) != "dir":
                    raise

    def walk(self, path: str = "/"):
        """como os.walk: genera (directorio, [subdirectorios], [archivos]) de arriba hacia abajo"""
        listing = self.ls(path)
        dirs = [d.rsplit("/", 1)[1] for d in listing["dirs"]]
        files = [f["path"].rsplit("/", 1)[1] for f in listing["files"]]
        yield path, dirs, files
        for d in dirs:
            yield from self.walk(path.rstrip("/") + "/" + d)

    def rm_tree(self, path: str):
        """borra un directorio con todo lo que tiene (o un archivo)"""
        if self.kind(path) != "dir":
            return self.rm(path)
        for dirpath, _dirs, files in reversed(list(self.walk(path))):
            for f in files:
                self.rm(dirpath.rstrip("/") + "/" + f)
            self.rmdir(dirpath)

    def put_tree(self, local_dir: str, remote_dir: str, block_size: Optional[int] = None, parallel: int = 3) -> int:
        """sube un directorio completo (varios archivos a la vez), devuelve cuántos archivos subió"""
        self.mkdir_p(remote_dir)
        jobs = []
        for root, dirs, files in os.walk(local_dir):
            rel = os.path.relpath(root, local_dir)
            target = remote_dir.rstrip("/") + ("" if rel == "." else "/" + rel.replace(os.sep, "/"))
            for d in dirs:
                self.mkdir_p(target + "/" + d)
            jobs += [(os.path.join(root, f), target + "/" + f) for f in files]
        with ThreadPoolExecutor(max_workers=parallel) as pool:
            list(pool.map(lambda j: self.put(j[0], j[1], block_size=block_size), jobs))
        return len(jobs)

    def get_tree(self, remote_dir: str, local_dir: str) -> int:
        """descarga un directorio completo, devuelve cuántos archivos bajó"""
        jobs = []
        for dirpath, dirs, files in self.walk(remote_dir):
            target = os.path.join(local_dir, os.path.relpath(dirpath, remote_dir)) if dirpath != remote_dir else local_dir
            os.makedirs(target, exist_ok=True)
            jobs += [(dirpath.rstrip("/") + "/" + f, os.path.join(target, f)) for f in files]
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda j: self.get(j[0], j[1]), jobs))
        return len(jobs)

    def cp(self, src: str, dst: str, recursive: bool = False) -> int:
        """copia dentro de dfsha pasando los datos por el cliente (los bloques son inmutables y se reescriben con sus propias réplicas), si dst es un directorio copia dentro de él"""
        if self.kind(dst) == "dir":
            dst = dst.rstrip("/") + "/" + src.rstrip("/").rsplit("/", 1)[1]
        if self.kind(src) == "dir":
            if not recursive:
                raise DFShaError("es un directorio: usa recursive=True")
            n = 0
            for dirpath, dirs, files in self.walk(src):
                target = dst + dirpath[len(src.rstrip("/")):]
                self.mkdir_p(target)
                for f in files:
                    n += self.cp(dirpath.rstrip("/") + "/" + f, target + "/" + f)
            return n
        info = self.stat(src)
        with self.open(src, "r") as fin, self.open(dst, "w", block_size=info["block_size"]) as fout:
            while chunk := fin.read(info["block_size"]):
                fout.write(chunk)
        return 1

    def open(self, path: str, mode: str = "r", block_size: Optional[int] = None,
             lock: Optional[str] = None, lock_timeout: float = 10.0) -> "DFShaFile":
        """abre un archivo con acceso aleatorio (rf3), modos binarios: r, r+, w, w+, a, a+; lock: None | 'shared' | 'exclusive' (se consigue esperando hasta lock_timeout)"""
        return DFShaFile(self, path, mode, block_size=block_size, lock=lock, lock_timeout=lock_timeout)

    # escritura

    @staticmethod
    def _write_block(block: dict, data: bytes, ca: Optional[str] = None) -> dict:
        """escribe el bloque en cada réplica con el token de escritura que dio el control node"""
        checksum = hashlib.sha256(data).hexdigest()
        written = []
        for rep in block["replicas"]:
            try:
                ack = dfsha_pb2_grpc.DataNodeStub(grpc_channel(rep["address"], ca)).WriteBlock(
                    dfsha_pb2.Block(block_id=block["block_id"], data=data, checksum=checksum),
                    timeout=60, metadata=(("x-dfsha-token", block["token"]),),
                )
                if ack.success:
                    written.append(rep["node_id"])
            except grpc.RpcError:
                pass
        return {"block_id": block["block_id"], "checksum": checksum, "written": written}

    def put(self, local_path: str, remote_path: str, block_size: Optional[int] = None,
            progress: Callable[[int, int, int, int], None] = None) -> dict:
        """sube un archivo, los bloques se escriben en paralelo (con ventana limitada) y en todas sus réplicas, progress(index, total, escritas, planeadas)"""
        size = os.path.getsize(local_path)
        body = {"path": remote_path, "size": size}
        if block_size:
            body["block_size"] = block_size
        plan = self._request("POST", "/files/init", json=body)
        blocks = plan["blocks"]
        # el lease es de la transferencia activa, no de cuánto dura en total, y los permisos también se renuevan mientras una llamada grpc está en curso
        renew_lock = threading.RLock()
        stop_renew = threading.Event()
        renew_errors = []
        renew_interval = max(0.01, float(plan.get("lease_ttl", 600)) / 3)
        renewed_at = time.monotonic()
        by_id = {b["block_id"]: b for b in blocks}

        def renew(force=False):
            nonlocal renewed_at
            with renew_lock:
                if renew_errors:
                    raise renew_errors[0]
                if stop_renew.is_set() or (not force and time.monotonic() - renewed_at < renew_interval):
                    return
                try:
                    fresh = self._request("POST", "/files/renew", json={"upload_id": plan["upload_id"]})
                    for b in fresh["blocks"]:
                        by_id[b["block_id"]].update(token=b["token"], replicas=b["replicas"])
                    renewed_at = time.monotonic()
                except Exception as e:
                    renew_errors.append(e)
                    raise

        def keepalive():
            while not stop_renew.wait(renew_interval):
                try:
                    renew()
                except Exception:
                    return  # el productor o escritor va a mostrar el error y abortar el upload

        def write_current(block, data):
            renew()  # se revisa al salir de la cola, no solo al programar el bloque
            with renew_lock:
                current = dict(block)
            result = self._write_block(current, data, self.ca)
            if not result["written"]:
                renew(force=True)
                with renew_lock:
                    current = dict(block)
                result = self._write_block(current, data, self.ca)
            return result

        renewal = threading.Thread(target=keepalive, daemon=True, name="dfsha-upload-keepalive")
        renewal.start()
        window = threading.BoundedSemaphore(PARALLEL_BLOCKS * 2)  # limita la memoria en uso
        results = []
        try:
            with ThreadPoolExecutor(max_workers=PARALLEL_BLOCKS) as pool, open(local_path, "rb") as f:
                futures = []
                for b in blocks:
                    with renew_lock:
                        if renew_errors:
                            raise renew_errors[0]
                    data = f.read(b["size"])
                    if len(data) != b["size"]:
                        raise DFShaError("el archivo cambió durante la subida")
                    window.acquire()
                    fut = pool.submit(write_current, b, data)
                    fut.add_done_callback(lambda _f: window.release())
                    futures.append((b, fut))
                for b, fut in futures:
                    res = fut.result()
                    if not res["written"]:
                        raise DFShaError(f"bloque {b['index']}: no se pudo escribir en ninguna réplica")
                    results.append(res)
                    if progress:
                        progress(b["index"], len(blocks), len(res["written"]), len(b["replicas"]))
            with renew_lock:
                if renew_errors:
                    raise renew_errors[0]
                # evita que una renovación choque con el borrado del upload al publicar
                stop_renew.set()
                return self._request("POST", "/files/complete",
                                     json={"upload_id": plan["upload_id"], "blocks": results})
        except BaseException:
            stop_renew.set()
            try:
                self._request("POST", "/files/abort", json={"upload_id": plan["upload_id"]})
            except DFShaError:
                pass
            raise
        finally:
            stop_renew.set()
            renewal.join(timeout=1)

    # lectura

    @staticmethod
    def _read_block(block: dict, ca: Optional[str] = None) -> bytes:
        errors = []
        for addr in block["replicas"]:
            try:
                blk = dfsha_pb2_grpc.DataNodeStub(grpc_channel(addr, ca)).ReadBlock(
                    dfsha_pb2.BlockId(block_id=block["block_id"]), timeout=60,
                    metadata=(("x-dfsha-token", block["token"]),))
                # el checksum de referencia es el de los metadatos y no el que devuelve el nodo (un nodo con el disco corrupto mentiría)
                if hashlib.sha256(blk.data).hexdigest() != block["checksum"]:
                    errors.append(f"{addr}: checksum no coincide")
                    continue
                return blk.data
            except grpc.RpcError as e:
                errors.append(f"{addr}: {e.details()}")
        raise DFShaError(f"bloque {block['index']} ilegible en todas sus réplicas ({'; '.join(errors) or 'sin réplicas vivas'})")

    def get(self, remote_path: str, local_path: str):
        tmp = local_path + ".part"
        try:
            # el handle retiene la versión mientras otros clientes la reemplazan o borran, read() baja cada ventana en paralelo y renueva tokens y direcciones si falla
            with self.open(remote_path, "r") as src, open(tmp, "wb") as out:
                size = src.size
                window_bytes = src.block_size * PARALLEL_BLOCKS * 2
                while chunk := src.read(window_bytes):
                    out.write(chunk)
                if out.tell() != size:
                    raise DFShaError("el tamaño reconstruido no coincide con el esperado")
            os.replace(tmp, local_path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise


class DFShaFile:
    """archivo abierto en dfsha (rf3) con interfaz tipo archivo binario de python y semántica de sesión como afs sobre bloques inmutables: open toma un snapshot y las lecturas ven ese snapshot más las escrituras propias, las escrituras quedan en memoria del cliente (bloques sucios) y flush()/close() las publican de forma atómica como versión nueva reescribiendo solo los bloques tocados, si otra sesión publicó antes el commit falla con 409 (control optimista) y con lock('exclusive') nadie más puede publicar (423), un hilo de keepalive mantiene vivos el handle y sus locks (si el cliente muere expiran solos en el servidor) y escribir más allá del final rellena los huecos con ceros (no hay archivos sparse)"""

    MAX_DIRTY_BYTES = 64 * 1024 * 1024  # al pasarlo, los bloques sucios se mandan a los datanodes (sin publicar)
    CACHE_BLOCKS = 8

    def __init__(self, client: DFShaClient, path: str, mode: str = "r",
                 block_size: Optional[int] = None, lock: Optional[str] = None, lock_timeout: float = 10.0):
        if mode not in ("r", "r+", "w", "w+", "a", "a+"):
            raise ValueError(f"modo inválido: {mode!r}")
        self.client, self.path, self.mode = client, path, mode
        self._readable = mode in ("r", "r+", "w+", "a+")
        self._writable = mode != "r"
        self._append = mode.startswith("a")
        body = {"path": path, "mode": mode}
        if block_size:
            body["block_size"] = block_size
        info = client._request("POST", "/fs/open", json=body)
        self.handle = info["handle"]
        self._closed = False
        self._dirty: dict[int, bytearray] = {}  # idx contenido del bloque modificado (en memoria)
        self._staged: dict[int, dict] = {}  # idx bloque ya escrito en los datanodes pero sin publicar
        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._prefetched: dict[str, bytes] = {}  # bloques bajados en paralelo para el read() que está en curso
        self._changed = False
        self._apply_info(info)
        self._pos = self.size if self._append else 0
        self._stop_keepalive = threading.Event()
        self._keepalive = threading.Thread(target=self._keepalive_loop, args=(info["lease_ttl"],),
                                           daemon=True, name="dfsha-keepalive")
        self._keepalive.start()
        try:
            if mode.startswith("w") and self.size > 0:
                self.truncate(0)
            if lock:
                self.lock(lock, timeout=lock_timeout)
        except BaseException:
            self.close(discard=True)
            raise

    # estado

    def _apply_info(self, info: dict):
        self.size = info["size"]
        self.block_size = info["block_size"]
        self.version = info["version"]
        self._blocks = {}
        for b in info["blocks"]:
            b = dict(b)
            b["valid"] = b["size"]  # bytes del bloque que siguen siendo contenido válido (truncate)
            self._blocks[b["index"]] = b
        self._staged = {}
        self._dirty = {}

    def _keepalive_loop(self, ttl: float):
        while not self._stop_keepalive.wait(max(0.01, ttl / 3)):
            try:
                self.client._request("POST", "/fs/keepalive", json={"handle": self.handle})
            except DFShaError as e:
                if e.status == 404:  # la sesión ya expiró en el servidor
                    return

    def _check_open(self):
        if self._closed:
            raise ValueError("archivo cerrado")

    def _L(self, idx: int) -> int:
        """largo válido del bloque idx según el tamaño actual"""
        return max(0, min(self.block_size, self.size - idx * self.block_size))

    def _nblocks(self) -> int:
        return -(-self.size // self.block_size)

    # e/s de bloques

    def _cache_put(self, block_id: str, data: bytes):
        self._cache[block_id] = data
        self._cache.move_to_end(block_id)
        while len(self._cache) > self.CACHE_BLOCKS:
            self._cache.popitem(last=False)

    def _refresh_addresses(self):
        info = self.client._request("POST", "/fs/resolve", json={"handle": self.handle})
        for b in info["blocks"]:
            if b["index"] in self._blocks and self._blocks[b["index"]]["block_id"] == b["block_id"]:
                self._blocks[b["index"]]["replicas"] = b["replicas"]
        for b in self._staged.values():
            if b["block_id"] in info["allocated_replicas"]:
                b["replicas"] = info["allocated_replicas"][b["block_id"]]["replicas"]
                b["token"] = info["allocated_replicas"][b["block_id"]]["token"]
        for b in info["blocks"]:  # también renueva los tokens 
            if b["index"] in self._blocks and self._blocks[b["index"]]["block_id"] == b["block_id"]:
                self._blocks[b["index"]]["token"] = b["token"]

    def _fetch(self, meta: dict) -> bytes:
        bid = meta["block_id"]
        if bid in self._prefetched:
            return self._prefetched[bid]
        if bid in self._cache:
            self._cache.move_to_end(bid)
            return self._cache[bid]
        try:
            data = DFShaClient._read_block(meta, self.client.ca)
        except DFShaError:
            self._refresh_addresses()  # los nodos o los tokens pudieron cambiar desde el open
            data = DFShaClient._read_block(meta, self.client.ca)
        self._cache_put(bid, data)
        return data

    def _meta(self, idx: int) -> Optional[dict]:
        return self._staged.get(idx) or self._blocks.get(idx)

    def _stored_view(self, idx: int, length: int) -> bytes:
        """contenido guardado del bloque, recortado a lo válido y rellenado con ceros hasta `length`"""
        meta = self._meta(idx)
        if meta is None or meta["valid"] == 0 or length == 0:
            return bytes(length)
        raw = self._fetch(meta)[:min(meta["valid"], length)]
        return raw + bytes(length - len(raw))

    def _dirty_buf(self, idx: int) -> bytearray:
        length = self._L(idx)
        buf = self._dirty.get(idx)
        if buf is None:
            buf = self._dirty[idx] = bytearray(self._stored_view(idx, length))
        elif len(buf) < length:
            buf.extend(bytes(length - len(buf)))
        elif len(buf) > length:
            del buf[length:]
        return buf

    def _block_view(self, idx: int) -> bytes:
        if idx in self._dirty:
            return bytes(self._dirty_buf(idx))
        return self._stored_view(idx, self._L(idx))

    def _prefetch(self, idxs: list[int]):
        todo = []
        for i in idxs:
            m = self._meta(i)
            if i not in self._dirty and m is not None and m["valid"] > 0 and m["block_id"] not in self._cache:
                todo.append(m)
        if len(todo) < 2:
            return
        with ThreadPoolExecutor(max_workers=PARALLEL_BLOCKS) as pool:
            results = list(pool.map(lambda m: self._try_read(m, self.client.ca), todo))
        self._prefetched = {m["block_id"]: d for m, d in zip(todo, results) if d is not None}

    @staticmethod
    def _try_read(meta: dict, ca: Optional[str] = None) -> Optional[bytes]:
        try:
            return DFShaClient._read_block(meta, ca)
        except DFShaError:
            return None  # _fetch lo reintenta refrescando las direcciones

    # api tipo archivo

    def readable(self) -> bool:
        return self._readable

    def writable(self) -> bool:
        return self._writable

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        self._check_open()
        base = {0: 0, 1: self._pos, 2: self.size}.get(whence)
        if base is None:
            raise ValueError("whence inválido")
        if base + offset < 0:
            raise ValueError("posición negativa")
        self._pos = base + offset
        return self._pos

    def read(self, n: int = -1) -> bytes:
        self._check_open()
        if not self._readable:
            raise IOError("el archivo no se abrió para lectura")
        end = self.size if n is None or n < 0 else min(self.size, self._pos + n)
        if self._pos >= end:
            return b""
        bs = self.block_size
        self._prefetch(list(range(self._pos // bs, (end - 1) // bs + 1)))
        try:
            out, pos = bytearray(), self._pos
            while pos < end:
                idx, off = divmod(pos, bs)
                take = min(end - pos, bs - off)
                out += self._block_view(idx)[off:off + take]
                pos += take
        finally:
            self._prefetched = {}
        self._pos = pos
        return bytes(out)

    def write(self, data) -> int:
        self._check_open()
        if not self._writable:
            raise IOError("el archivo no se abrió para escritura")
        data = bytes(data)
        if not data:
            return 0
        if self._append:
            self._pos = self.size
        start, end, bs = self._pos, self._pos + len(data), self.block_size
        if end > self.size:
            self.size = end
        pos, done = start, 0
        while pos < end:
            idx, off = divmod(pos, bs)
            take = min(end - pos, bs - off)
            self._dirty_buf(idx)[off:off + take] = data[done:done + take]
            pos += take
            done += take
        self._pos = end
        self._changed = True
        if sum(len(b) for b in self._dirty.values()) > self.MAX_DIRTY_BYTES:
            self._stage()
        return len(data)

    def truncate(self, size: Optional[int] = None) -> int:
        self._check_open()
        if not self._writable:
            raise IOError("el archivo no se abrió para escritura")
        size = self._pos if size is None else size
        if size < 0:
            raise ValueError("tamaño negativo")
        if size < self.size:
            bs = self.block_size
            keep = -(-size // bs)
            for idx in [i for i in self._dirty if i >= keep]:
                del self._dirty[idx]
            for idx in [i for i in self._staged if i >= keep]:
                del self._staged[idx]
            for idx, meta in list(self._blocks.items()) + list(self._staged.items()):
                meta["valid"] = min(meta["valid"], max(0, size - idx * bs))
            self.size = size
            for idx in list(self._dirty):  # se recorta de una vez para que no "revivan" bytes cuando el archivo vuelve a crecer
                self._dirty_buf(idx)
        else:
            self.size = size
        self._changed = True
        return size

    # publicación

    def _stage(self, include_rewrites: bool = False):
        """escribe en los datanodes (sin publicar) los bloques sucios y, si se pide, los que hay que reescribir porque cambió su tamaño o quedaron huecos"""
        idxs = set(self._dirty)
        if include_rewrites:
            for idx in range(self._nblocks()):
                meta = self._meta(idx)
                if idx not in self._dirty and (meta is None or meta["size"] != self._L(idx)
                                               or meta["valid"] < self._L(idx)):
                    idxs.add(idx)
        order = sorted(idxs)
        batch_size = PARALLEL_BLOCKS * 2
        for i in range(0, len(order), batch_size):
            batch = order[i:i + batch_size]
            contents = {idx: self._block_view(idx) for idx in batch}
            alloc = self.client._request("POST", "/fs/alloc", json={
                "handle": self.handle, "sizes": [len(contents[idx]) for idx in batch]})["blocks"]
            with ThreadPoolExecutor(max_workers=PARALLEL_BLOCKS) as pool:
                results = list(pool.map(lambda p: DFShaClient._write_block(p[0], p[1], self.client.ca),
                                        [(a, contents[idx]) for a, idx in zip(alloc, batch)]))
            for idx, a, res in zip(batch, alloc, results):
                if not res["written"]:
                    raise DFShaError(f"bloque {idx}: no se pudo escribir en ninguna réplica")
                addr = {r["node_id"]: r["address"] for r in a["replicas"]}
                self._staged[idx] = {
                    "block_id": a["block_id"], "index": idx, "size": len(contents[idx]),
                    "checksum": res["checksum"], "written": res["written"], "valid": len(contents[idx]),
                    "replicas": [addr[n] for n in res["written"]], "token": a["read_token"],
                }
                self._cache_put(a["block_id"], contents[idx])
                self._dirty.pop(idx, None)

    def flush(self):
        """publica los cambios como versión nueva (commit atómico)"""
        self._check_open()
        if not self._writable or not self._changed:
            return
        self._stage(include_rewrites=True)
        blocks = []
        for idx in range(self._nblocks()):
            if idx in self._staged:
                m = self._staged[idx]
                blocks.append({"block_id": m["block_id"], "size": m["size"],
                               "checksum": m["checksum"], "written": m["written"]})
            else:
                m = self._blocks[idx]
                blocks.append({"block_id": m["block_id"], "size": m["size"],
                               "checksum": m["checksum"], "written": None})
        info = self.client._request("POST", "/fs/commit", json={
            "handle": self.handle, "size": self.size, "blocks": blocks})
        self._apply_info(info)
        self._changed = False

    # locks

    def lock(self, mode: str = "exclusive", timeout: float = 10.0, poll: float = 0.2):
        """consigue un lock 'shared' o 'exclusive' esperando hasta `timeout` segundos (423 si no se logra), si no hay cambios locales sin publicar al obtenerlo se actualiza el snapshot a la versión actual (otra sesión pudo publicar mientras esperaba)"""
        self._check_open()
        deadline = time.time() + timeout
        while True:
            try:
                self.client._request("POST", "/fs/lock", json={"handle": self.handle, "mode": mode})
                break
            except DFShaError as e:
                if e.status != 423 or time.time() >= deadline:
                    raise
                time.sleep(poll)
        if not self._changed:
            self.refresh()

    def refresh(self):
        """descarta el snapshot y vuelve a leer la versión actual (solo si no hay cambios pendientes)"""
        self._check_open()
        if self._changed:
            raise DFShaError("hay cambios sin publicar: usa flush() o ciérralo con discard")
        self._apply_info(self.client._request("POST", "/fs/refresh", json={"handle": self.handle}))

    def unlock(self):
        self._check_open()
        self.client._request("POST", "/fs/lock", json={"handle": self.handle, "mode": "none"})

    # cierre

    def close(self, discard: bool = False):
        """publica los cambios pendientes (salvo discard=True) y cierra la sesión soltando sus locks"""
        if self._closed:
            return
        try:
            if self._writable and self._changed and not discard:
                self.flush()
        finally:
            self._closed = True
            self._stop_keepalive.set()
            try:
                self.client._request("POST", "/fs/close", json={"handle": self.handle})
            except DFShaError:
                pass

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close(discard=exc_type is not None)  # si hubo una excepción se descartan los cambios
        return False
