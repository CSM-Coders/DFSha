"""máquina de estados de los metadatos: una base sqlite en memoria que cada nodo reconstruye desde el log de raft (journal + snapshot), las mutaciones son operaciones deterministas registradas en OPS (el líder fija `now` y los ids antes de replicarlas) y las lecturas son locales, por eso aquí no se lee el reloj ni se generan ids; tablas: users (cuentas, época de tokens y 2fa), groups, acl (permisos 'r' o 'rw' que se heredan por el árbol), apikeys (solo el hash), dirs (con dueño, '/' es de todos), files (archivos completos, cada bloque con node_ids, sha256 y tamaño, `version` sube en cada commit), uploads (puts en curso, un archivo solo pasa a files con el commit atómico así que un put a medias nunca se ve), handles (sesiones open/read/write/close con el snapshot de bloques y los bloques nuevos sin publicar, el lease no se replica y `base_version = -1` deja terminar de leer un archivo borrado pero nunca escribir) y locks (compartidos o exclusivos atados a un handle); todo pasa por _lock (rlock) porque el hilo de raft aplica operaciones mientras los hilos http leen"""
import json
import sqlite3
import posixpath
import threading
from contextlib import contextmanager

_lock = threading.RLock()
_conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
_conn.row_factory = sqlite3.Row

OPS: dict = {}  # nombre -> función de mutación replicable


def _op(fn):
    OPS[fn.__name__] = fn
    return fn


def _parent(path: str) -> str:
    return posixpath.dirname(path) or "/"


class Locked(Exception):
    """el archivo está bloqueado por otra sesión"""


class Conflict(Exception):
    """la operación contradice el estado actual (versión, namespace o seguridad)"""


class Gone(Exception):
    """el handle, archivo o directorio que se pidió ya no existe"""


def _require_parent(c, path: str):
    """revisa el padre dentro de la misma transacción que cambia el namespace"""
    if not c.execute("SELECT 1 FROM dirs WHERE path = ?", (_parent(path),)).fetchone():
        raise Gone("directorio padre")


def _require_file_path(c, path: str):
    """un destino de archivo tiene que tener padre y nunca ser un directorio"""
    if c.execute("SELECT 1 FROM dirs WHERE path = ?", (path,)).fetchone():
        raise Conflict("la ruta corresponde a un directorio")
    _require_parent(c, path)


@contextmanager
def _tx():
    with _lock:
        _conn.execute("BEGIN IMMEDIATE")
        try:
            yield _conn
            _conn.execute("COMMIT")
        except BaseException:
            _conn.execute("ROLLBACK")
            raise


_SCHEMA = [
    "CREATE TABLE users ("
    " username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,"
    " token_epoch INTEGER NOT NULL DEFAULT 0, totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE dirs ("
    " path TEXT PRIMARY KEY, owner TEXT NOT NULL, parent TEXT NOT NULL)",
    "CREATE INDEX dirs_parent ON dirs (parent)",
    "CREATE TABLE files ("
    " path TEXT PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL,"
    " block_size INTEGER NOT NULL, blocks TEXT NOT NULL, created_at REAL NOT NULL,"
    " version INTEGER NOT NULL DEFAULT 1, parent TEXT NOT NULL)",
    "CREATE INDEX files_parent ON files (parent)",
    "CREATE TABLE uploads ("
    " upload_id TEXT PRIMARY KEY, path TEXT NOT NULL, owner TEXT NOT NULL,"
    " size INTEGER NOT NULL, block_size INTEGER NOT NULL, blocks TEXT NOT NULL,"
    " created_at REAL NOT NULL)",
    "CREATE TABLE handles ("
    " handle_id TEXT PRIMARY KEY, path TEXT NOT NULL, owner TEXT NOT NULL,"
    " writable INTEGER NOT NULL, base_version INTEGER NOT NULL, size INTEGER NOT NULL,"
    " block_size INTEGER NOT NULL, blocks TEXT NOT NULL, allocated TEXT NOT NULL,"
    " created_at REAL NOT NULL)",
    "CREATE TABLE locks ("
    " path TEXT NOT NULL, handle_id TEXT NOT NULL, mode TEXT NOT NULL,"
    " PRIMARY KEY (path, handle_id))",
    "CREATE TABLE groups (name TEXT PRIMARY KEY, owner TEXT NOT NULL)",
    "CREATE TABLE group_members (group_name TEXT NOT NULL, username TEXT NOT NULL,"
    " PRIMARY KEY (group_name, username))",
    "CREATE INDEX group_members_user ON group_members (username)",
    "CREATE TABLE acl (path TEXT NOT NULL, principal TEXT NOT NULL, perm TEXT NOT NULL,"
    " PRIMARY KEY (path, principal))",
    "CREATE INDEX acl_principal ON acl (principal)",
    "CREATE TABLE apikeys (key_id TEXT PRIMARY KEY, owner TEXT NOT NULL, secret_hash TEXT NOT NULL,"
    " label TEXT NOT NULL, created_at REAL NOT NULL)",
]


@_op
def noop():
    """barrera: cuando se confirma, el líder sabe que aplicó todo lo anterior en su término"""
    return None


def init_db():
    """estado inicial (igual en todos los nodos): el esquema y el directorio raíz"""
    with _tx() as c:
        for (name,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            c.execute(f"DROP TABLE {name}")
        for stmt in _SCHEMA:
            c.execute(stmt)
        c.execute("INSERT INTO dirs (path, owner, parent) VALUES ('/', '', '/')")


def dump() -> bytes:
    """foto de todo el estado (para compactar el log de raft)"""
    with _lock:
        return _conn.serialize()


def load(data: bytes):
    """reemplaza todo el estado con un snapshot recibido"""
    with _lock:
        _conn.deserialize(data)


# usuarios

def get_user_hash(username: str):
    with _lock:
        row = _conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row["password_hash"] if row else None


@_op
def register_user(username: str, password_hash: str) -> str:
    """crea el usuario y su directorio home /<usuario>, devuelve 'ok' | 'exists' | 'name_taken'"""
    home = "/" + username
    with _tx() as c:
        if c.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            return "exists"
        if c.execute("SELECT 1 FROM dirs WHERE path = ? UNION SELECT 1 FROM files WHERE path = ?",
                     (home, home)).fetchone():
            return "name_taken"
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        c.execute("INSERT INTO dirs (path, owner, parent) VALUES (?, ?, '/')", (home, username))
        return "ok"


def get_user(username: str):
    with _lock:
        r = _conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not r:
        return None
    return {"username": r["username"], "password_hash": r["password_hash"], "epoch": r["token_epoch"],
            "totp_secret": r["totp_secret"], "totp_enabled": bool(r["totp_enabled"])}


def user_exists(username: str) -> bool:
    with _lock:
        return _conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone() is not None


@_op
def set_password(username: str, password_hash: str) -> bool:
    """cambia la contraseña y revoca todas las sesiones (sube la época de tokens)"""
    with _tx() as c:
        cur = c.execute("UPDATE users SET password_hash = ?, token_epoch = token_epoch + 1 WHERE username = ?",
                        (password_hash, username))
        return cur.rowcount > 0


@_op
def bump_epoch(username: str) -> int:
    """revoca todas las sesiones (tokens) vigentes del usuario"""
    with _tx() as c:
        c.execute("UPDATE users SET token_epoch = token_epoch + 1 WHERE username = ?", (username,))
        return c.execute("SELECT token_epoch FROM users WHERE username = ?", (username,)).fetchone()[0]


@_op
def totp_setup(username: str, secret: str):
    """guarda un secreto totp pendiente de confirmar (no pide 2fa hasta totp_enable)"""
    with _tx() as c:
        row = c.execute("SELECT totp_enabled FROM users WHERE username = ?", (username,)).fetchone()
        if row and row["totp_enabled"]:
            raise Conflict("2FA ya está activado; desactívalo antes de configurarlo de nuevo")
        c.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE username = ?", (secret, username))


@_op
def totp_enable(username: str) -> bool:
    with _tx() as c:
        cur = c.execute("UPDATE users SET totp_enabled = 1 WHERE username = ? AND totp_secret IS NOT NULL", (username,))
        return cur.rowcount > 0


@_op
def totp_disable(username: str):
    with _tx() as c:
        c.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE username = ?", (username,))


def has_users() -> bool:
    with _lock:
        return _conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


# directorios

def get_dir_owner(path: str):
    with _lock:
        row = _conn.execute("SELECT owner FROM dirs WHERE path = ?", (path,)).fetchone()
    return row["owner"] if row else None


@_op
def add_dir(path: str, owner: str) -> bool:
    with _tx() as c:
        if c.execute("SELECT 1 FROM files WHERE path = ?", (path,)).fetchone():
            raise Conflict("la ruta corresponde a un archivo")
        _require_parent(c, path)
        cur = c.execute("INSERT OR IGNORE INTO dirs (path, owner, parent) VALUES (?, ?, ?)",
                        (path, owner, _parent(path)))
        return cur.rowcount > 0


@_op
def remove_dir(path: str):
    with _tx() as c:
        if path == "/":
            raise Conflict("no se puede borrar la raíz")
        if c.execute("SELECT 1 FROM files WHERE path = ?", (path,)).fetchone():
            raise Conflict("la ruta corresponde a un archivo")
        if not c.execute("SELECT 1 FROM dirs WHERE path = ?", (path,)).fetchone():
            return
        if (c.execute("SELECT 1 FROM files WHERE parent = ? LIMIT 1", (path,)).fetchone()
                or c.execute("SELECT 1 FROM dirs WHERE parent = ? LIMIT 1", (path,)).fetchone()):
            raise Conflict("directorio no vacío")
        c.execute("DELETE FROM dirs WHERE path = ?", (path,))
        c.execute("DELETE FROM acl WHERE path = ?", (path,))


def dir_owners(paths: list[str]) -> dict:
    """path -> dueño, de los directorios que existan entre `paths`"""
    if not paths:
        return {}
    with _lock:
        rows = _conn.execute(f"SELECT path, owner FROM dirs WHERE path IN ({','.join('?' * len(paths))})", paths).fetchall()
    return {r["path"]: r["owner"] for r in rows}


def child_dirs(path: str) -> list[dict]:
    with _lock:
        rows = _conn.execute("SELECT path, owner FROM dirs WHERE parent = ? AND path != '/'", (path,)).fetchall()
    return [{"path": r["path"], "owner": r["owner"]} for r in rows]


def child_files(path: str) -> list[dict]:
    with _lock:
        rows = _conn.execute("SELECT path, owner, size, version, created_at FROM files WHERE parent = ?", (path,)).fetchall()
    return [{"path": r["path"], "owner": r["owner"], "size": r["size"], "version": r["version"],
             "mtime": r["created_at"]} for r in rows]


def has_children(path: str) -> bool:
    """true si el directorio tiene algún archivo o subdirectorio directo"""
    with _lock:
        return (_conn.execute("SELECT 1 FROM files WHERE parent = ? LIMIT 1", (path,)).fetchone() is not None
                or _conn.execute("SELECT 1 FROM dirs WHERE parent = ? AND path != '/' LIMIT 1", (path,)).fetchone() is not None)


# archivos

def _file_meta(row) -> dict:
    return {
        "owner": row["owner"],
        "size": row["size"],
        "block_size": row["block_size"],
        "blocks": json.loads(row["blocks"]),
        "created_at": row["created_at"],
        "version": row["version"],
    }


def get_file(path: str):
    with _lock:
        row = _conn.execute("SELECT * FROM files WHERE path = ?", (path,)).fetchone()
    return _file_meta(row) if row else None


def list_files(owner: str = None) -> dict:
    with _lock:
        if owner is None:
            rows = _conn.execute("SELECT * FROM files").fetchall()
        else:
            rows = _conn.execute("SELECT * FROM files WHERE owner = ?", (owner,)).fetchall()
    return {r["path"]: _file_meta(r) for r in rows}


@_op
def create_empty_file(path: str, owner: str, block_size: int, now: float) -> bool:
    """crea un archivo vacío (versión 1), false si ya existía"""
    with _tx() as c:
        _require_file_path(c, path)
        cur = c.execute(
            "INSERT OR IGNORE INTO files (path, owner, size, block_size, blocks, created_at, version, parent)"
            " VALUES (?, ?, 0, ?, '[]', ?, 1, ?)",
            (path, owner, block_size, now, _parent(path)),
        )
        return cur.rowcount > 0


def file_block_nodes(path: str) -> dict:
    """block_id -> node_ids de la versión actual del archivo"""
    f = get_file(path)
    return {b["block_id"]: b["nodes"] for b in f["blocks"]} if f else {}


@_op
def delete_file(path: str):
    """borra el archivo y devuelve su metadato (o None si no existía), lanza Locked si otra sesión lo tiene bloqueado"""
    with _tx() as c:
        row = c.execute("SELECT * FROM files WHERE path = ?", (path,)).fetchone()
        if not row:
            return None
        if c.execute("SELECT 1 FROM locks WHERE path = ? LIMIT 1", (path,)).fetchone():
            raise Locked(path)
        c.execute("DELETE FROM files WHERE path = ?", (path,))
        c.execute("DELETE FROM acl WHERE path = ?", (path,))
        # se mantienen los bloques del snapshot hasta cerrar o expirar el handle, sin dejar que una versión 1 nueva en la misma ruta lo reactive
        c.execute("UPDATE handles SET base_version = -1 WHERE path = ?", (path,))
        return _file_meta(row)


@_op
def update_block_nodes(path: str, block_id: str, add: str = None, remove: str = None) -> bool:
    """añade o quita un node_id de las réplicas de un bloque, false si el archivo o el bloque ya no existen (por ejemplo se borró mientras se re-replicaba)"""
    with _tx() as c:
        row = c.execute("SELECT blocks FROM files WHERE path = ?", (path,)).fetchone()
        if not row:
            return False
        blocks = json.loads(row["blocks"])
        for b in blocks:
            if b["block_id"] == block_id:
                if add and add not in b["nodes"]:
                    b["nodes"].append(add)
                if remove and remove in b["nodes"]:
                    b["nodes"].remove(remove)
                c.execute("UPDATE files SET blocks = ? WHERE path = ?", (json.dumps(blocks), path))
                return True
        return False


@_op
def drop_replica(block_id: str, node_id: str) -> list:
    """quita a un nodo de las réplicas de un bloque en todos los archivos que lo usan (por ejemplo su copia está corrupta), devuelve los paths afectados y el monitor repone la réplica en otro nodo"""
    affected = []
    with _tx() as c:
        rows = c.execute("SELECT path, blocks FROM files WHERE blocks LIKE ?", (f'%"{block_id}"%',)).fetchall()
        for r in rows:
            blocks = json.loads(r["blocks"])
            changed = False
            for b in blocks:
                if b["block_id"] == block_id and node_id in b["nodes"]:
                    b["nodes"].remove(node_id)
                    changed = True
            if changed:
                c.execute("UPDATE files SET blocks = ? WHERE path = ?", (json.dumps(blocks), r["path"]))
                affected.append(r["path"])
    return affected


@_op
def drop_missing_replicas(node_id: str, block_ids: list[str]) -> list[str]:
    """retira un inventario de copias faltantes en una sola operación raft, recorre cada archivo una vez sin tocar bloques de otros nodos y reenviar el mismo reporte no cambia nada"""
    missing = set(block_ids)
    if not missing:
        return []
    affected = []
    with _tx() as c:
        rows = c.execute("SELECT path, blocks FROM files ORDER BY path").fetchall()
        for row in rows:
            blocks = json.loads(row["blocks"])
            changed = False
            for block in blocks:
                if block["block_id"] in missing and node_id in block["nodes"]:
                    block["nodes"].remove(node_id)
                    changed = True
            if changed:
                c.execute("UPDATE files SET blocks = ? WHERE path = ?", (json.dumps(blocks), row["path"]))
                affected.append(row["path"])
    return affected


def _under(c, table: str, src: str) -> list:
    """paths de `table` iguales a src o dentro de src/"""
    return [r["path"] for r in c.execute(
        f"SELECT path FROM {table} WHERE path = ? OR substr(path, 1, ?) = ?", (src, len(src) + 1, src + "/")).fetchall()]


@_op
def rename_path(src: str, dst: str) -> str:
    """mueve o renombra un archivo o directorio con todo lo que tiene, de forma atómica (las acl y las sesiones abiertas lo siguen), devuelve 'ok' | 'src_missing' | 'dst_exists' | 'dst_parent_missing' | 'into_itself' | 'locked'"""
    with _tx() as c:
        is_file = c.execute("SELECT 1 FROM files WHERE path = ?", (src,)).fetchone() is not None
        is_dir = c.execute("SELECT 1 FROM dirs WHERE path = ?", (src,)).fetchone() is not None
        if not (is_file or is_dir):
            return "src_missing"
        if dst == src:
            return "ok"
        if c.execute("SELECT 1 FROM files WHERE path = ? UNION SELECT 1 FROM dirs WHERE path = ?", (dst, dst)).fetchone():
            return "dst_exists"
        if not c.execute("SELECT 1 FROM dirs WHERE path = ?", (_parent(dst),)).fetchone():
            return "dst_parent_missing"
        if is_dir and (dst + "/").startswith(src + "/"):
            return "into_itself"
        if any(_under(c, "locks", src)):
            return "locked"
        moved = lambda p: dst + p[len(src):]
        for p in _under(c, "files", src):
            c.execute("UPDATE files SET path = ?, parent = ? WHERE path = ?", (moved(p), _parent(moved(p)), p))
        for p in _under(c, "dirs", src):
            c.execute("UPDATE dirs SET path = ?, parent = ? WHERE path = ?", (moved(p), _parent(moved(p)), p))
        for table in ("acl", "handles", "uploads"):
            for p in _under(c, table, src):
                c.execute(f"UPDATE {table} SET path = ? WHERE path = ?", (moved(p), p))
        return "ok"


# uploads (transferencia: put)

@_op
def create_upload(upload_id: str, path: str, owner: str, size: int, block_size: int, blocks: list, now: float):
    with _tx() as c:
        _require_file_path(c, path)
        c.execute(
            "INSERT INTO uploads (upload_id, path, owner, size, block_size, blocks, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (upload_id, path, owner, size, block_size, json.dumps(blocks), now),
        )


def _upload_meta(row) -> dict:
    return {
        "path": row["path"],
        "owner": row["owner"],
        "size": row["size"],
        "block_size": row["block_size"],
        "blocks": json.loads(row["blocks"]),
        "created_at": row["created_at"],
    }


def get_upload(upload_id: str):
    with _lock:
        row = _conn.execute("SELECT * FROM uploads WHERE upload_id = ?", (upload_id,)).fetchone()
    return _upload_meta(row) if row else None


@_op
def refresh_upload(upload_id: str, now: float):
    """renueva el lease replicado, devuelve el upload actual o None si expiró"""
    with _tx() as c:
        row = c.execute("SELECT * FROM uploads WHERE upload_id = ?", (upload_id,)).fetchone()
        if not row:
            return None
        _require_file_path(c, row["path"])
        # un retraso entre solicitudes o un ajuste del reloj no acorta el lease
        c.execute("UPDATE uploads SET created_at = MAX(created_at, ?) WHERE upload_id = ?", (now, upload_id))
        return _upload_meta(c.execute("SELECT * FROM uploads WHERE upload_id = ?", (upload_id,)).fetchone())


@_op
def delete_upload(upload_id: str, stale_before: float = None):
    """borra el upload, opcionalmente solo si sigue vencido al aplicar la operación, devuelve su metadato o None si no existe o se renovó después de planear el gc"""
    with _tx() as c:
        row = c.execute("SELECT * FROM uploads WHERE upload_id = ?", (upload_id,)).fetchone()
        if not row:
            return None
        if stale_before is not None and row["created_at"] >= stale_before:
            return None
        c.execute("DELETE FROM uploads WHERE upload_id = ?", (upload_id,))
        return _upload_meta(row)


def stale_uploads(cutoff: float) -> list[str]:
    with _lock:
        rows = _conn.execute(
            "SELECT upload_id FROM uploads WHERE created_at < ?", (cutoff,)
        ).fetchall()
    return [r["upload_id"] for r in rows]


@_op
def commit_upload(upload_id: str, blocks: list, now: float):
    """publica el upload como versión actual del archivo de forma atómica, devuelve la lista de bloques de la versión anterior ([] si no había) o None si el upload ya no existe, lanza Locked si otra sesión bloquea el archivo"""
    with _tx() as c:
        up = c.execute("SELECT * FROM uploads WHERE upload_id = ?", (upload_id,)).fetchone()
        if not up:
            return None
        _require_file_path(c, up["path"])
        if c.execute("SELECT 1 FROM locks WHERE path = ? LIMIT 1", (up["path"],)).fetchone():
            raise Locked(up["path"])
        old = c.execute("SELECT blocks FROM files WHERE path = ?", (up["path"],)).fetchone()
        c.execute(
            "INSERT INTO files (path, owner, size, block_size, blocks, created_at, version, parent)"
            " VALUES (?, ?, ?, ?, ?, ?, 1, ?)"
            " ON CONFLICT(path) DO UPDATE SET size=excluded.size,"  # se conserva el dueño original
            " block_size=excluded.block_size, blocks=excluded.blocks, created_at=excluded.created_at,"
            " version=files.version + 1",
            (up["path"], up["owner"], up["size"], up["block_size"], json.dumps(blocks), now, _parent(up["path"])),
        )
        c.execute("DELETE FROM uploads WHERE upload_id = ?", (upload_id,))
        return json.loads(old["blocks"]) if old else []


# locks

def is_locked(path: str) -> bool:
    with _lock:
        return _conn.execute("SELECT 1 FROM locks WHERE path = ? LIMIT 1", (path,)).fetchone() is not None


def locks_for(path: str) -> list[dict]:
    with _lock:
        rows = _conn.execute("SELECT handle_id, mode FROM locks WHERE path = ?", (path,)).fetchall()
    return [{"handle": r["handle_id"], "mode": r["mode"]} for r in rows]


@_op
def acquire_lock(path: str, handle_id: str, mode: str) -> bool:
    """consigue (o convierte) un lock 'shared' | 'exclusive', no bloquea y devuelve false si otro handle tiene un lock incompatible"""
    with _tx() as c:
        h = c.execute("SELECT path, base_version FROM handles WHERE handle_id = ?", (handle_id,)).fetchone()
        if not h:
            raise Gone("handle")
        if h["base_version"] < 0 or h["path"] != path:
            raise Gone("archivo del handle")
        if not c.execute("SELECT 1 FROM files WHERE path = ?", (path,)).fetchone():
            raise Gone("archivo")
        others = c.execute(
            "SELECT mode FROM locks WHERE path = ? AND handle_id != ?", (path, handle_id)
        ).fetchall()
        if mode == "exclusive" and others:
            return False
        if mode == "shared" and any(r["mode"] == "exclusive" for r in others):
            return False
        c.execute(
            "INSERT INTO locks (path, handle_id, mode) VALUES (?, ?, ?)"
            " ON CONFLICT(path, handle_id) DO UPDATE SET mode = excluded.mode",
            (path, handle_id, mode),
        )
        return True


@_op
def release_lock(path: str, handle_id: str):
    with _tx() as c:
        c.execute("DELETE FROM locks WHERE path = ? AND handle_id = ?", (path, handle_id))


# grupos

@_op
def create_group(name: str, owner: str) -> bool:
    with _tx() as c:
        cur = c.execute("INSERT OR IGNORE INTO groups (name, owner) VALUES (?, ?)", (name, owner))
        if cur.rowcount:
            c.execute("INSERT INTO group_members (group_name, username) VALUES (?, ?)", (name, owner))
        return cur.rowcount > 0


@_op
def delete_group(name: str) -> bool:
    with _tx() as c:
        cur = c.execute("DELETE FROM groups WHERE name = ?", (name,))
        c.execute("DELETE FROM group_members WHERE group_name = ?", (name,))
        c.execute("DELETE FROM acl WHERE principal = ?", ("group:" + name,))
        return cur.rowcount > 0


@_op
def group_member(name: str, username: str, add: bool) -> bool:
    with _tx() as c:
        if add:
            cur = c.execute("INSERT OR IGNORE INTO group_members (group_name, username) VALUES (?, ?)", (name, username))
        else:
            cur = c.execute("DELETE FROM group_members WHERE group_name = ? AND username = ?", (name, username))
        return cur.rowcount > 0


def get_group(name: str):
    with _lock:
        g = _conn.execute("SELECT owner FROM groups WHERE name = ?", (name,)).fetchone()
        if not g:
            return None
        members = [r["username"] for r in _conn.execute(
            "SELECT username FROM group_members WHERE group_name = ? ORDER BY username", (name,)).fetchall()]
    return {"name": name, "owner": g["owner"], "members": members}


def groups_of(username: str) -> list[str]:
    with _lock:
        rows = _conn.execute("SELECT group_name FROM group_members WHERE username = ?", (username,)).fetchall()
    return [r["group_name"] for r in rows]


# acl

@_op
def set_acl(path: str, principal: str, perm: str) -> None:
    """perm: 'r' | 'rw' | 'none' (quita la entrada)"""
    with _tx() as c:
        if perm == "none":
            c.execute("DELETE FROM acl WHERE path = ? AND principal = ?", (path, principal))
        else:
            c.execute("INSERT INTO acl (path, principal, perm) VALUES (?, ?, ?)"
                      " ON CONFLICT(path, principal) DO UPDATE SET perm = excluded.perm", (path, principal, perm))


def acl_for(path: str) -> list[dict]:
    with _lock:
        rows = _conn.execute("SELECT principal, perm FROM acl WHERE path = ? ORDER BY principal", (path,)).fetchall()
    return [{"principal": r["principal"], "perm": r["perm"]} for r in rows]


def acl_perms(paths: list[str], principals: list[str]) -> dict:
    """path -> permiso más alto ('r' | 'rw') que tenga alguno de los principals en ese path"""
    if not paths or not principals:
        return {}
    q = (f"SELECT path, perm FROM acl WHERE path IN ({','.join('?' * len(paths))})"
         f" AND principal IN ({','.join('?' * len(principals))})")
    with _lock:
        rows = _conn.execute(q, [*paths, *principals]).fetchall()
    out: dict = {}
    for r in rows:
        if out.get(r["path"]) != "rw":
            out[r["path"]] = r["perm"]
    return out


def shared_with(principals: list[str]) -> list[dict]:
    """entradas de acl que le llegan a alguno de los principals (lo que otros compartieron conmigo)"""
    if not principals:
        return []
    with _lock:
        rows = _conn.execute(f"SELECT path, principal, perm FROM acl WHERE principal IN ({','.join('?' * len(principals))})"
                             " ORDER BY path", principals).fetchall()
    return [{"path": r["path"], "principal": r["principal"], "perm": r["perm"]} for r in rows]


# api keys

@_op
def create_apikey(key_id: str, owner: str, secret_hash: str, label: str, now: float) -> bool:
    with _tx() as c:
        cur = c.execute("INSERT OR IGNORE INTO apikeys (key_id, owner, secret_hash, label, created_at)"
                        " VALUES (?, ?, ?, ?, ?)", (key_id, owner, secret_hash, label, now))
        return cur.rowcount > 0


@_op
def delete_apikey(key_id: str, owner: str) -> bool:
    with _tx() as c:
        return c.execute("DELETE FROM apikeys WHERE key_id = ? AND owner = ?", (key_id, owner)).rowcount > 0


def get_apikey(key_id: str):
    with _lock:
        r = _conn.execute("SELECT * FROM apikeys WHERE key_id = ?", (key_id,)).fetchone()
    return dict(r) if r else None


def list_apikeys(owner: str) -> list[dict]:
    with _lock:
        rows = _conn.execute("SELECT key_id, label, created_at FROM apikeys WHERE owner = ? ORDER BY created_at",
                             (owner,)).fetchall()
    return [dict(r) for r in rows]


# handles (acceso tipo archivo, rf3)

def _handle_meta(row) -> dict:
    return {
        "handle_id": row["handle_id"],
        "path": row["path"],
        "owner": row["owner"],
        "writable": bool(row["writable"]),
        "base_version": row["base_version"],
        "size": row["size"],
        "block_size": row["block_size"],
        "blocks": json.loads(row["blocks"]),
        "allocated": json.loads(row["allocated"]),
    }


@_op
def open_handle(handle_id: str, path: str, owner: str, writable: bool, now: float):
    """crea un handle con snapshot de la versión actual, None si el archivo no existe"""
    with _tx() as c:
        f = c.execute("SELECT * FROM files WHERE path = ?", (path,)).fetchone()
        if not f:
            return None
        c.execute(
            "INSERT INTO handles (handle_id, path, owner, writable, base_version, size, block_size,"
            " blocks, allocated, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', ?)",
            (handle_id, path, owner, int(writable), f["version"], f["size"], f["block_size"],
             f["blocks"], now),
        )
        row = c.execute("SELECT * FROM handles WHERE handle_id = ?", (handle_id,)).fetchone()
        return _handle_meta(row)


def get_handle(handle_id: str):
    with _lock:
        row = _conn.execute("SELECT * FROM handles WHERE handle_id = ?", (handle_id,)).fetchone()
    return _handle_meta(row) if row else None


@_op
def delete_handle(handle_id: str):
    """cierra el handle (y libera sus locks), devuelve su metadato o None"""
    with _tx() as c:
        row = c.execute("SELECT * FROM handles WHERE handle_id = ?", (handle_id,)).fetchone()
        if not row:
            return None
        c.execute("DELETE FROM locks WHERE handle_id = ?", (handle_id,))
        c.execute("DELETE FROM handles WHERE handle_id = ?", (handle_id,))
        return _handle_meta(row)


def handle_ids() -> list[str]:
    with _lock:
        return [r["handle_id"] for r in _conn.execute("SELECT handle_id FROM handles").fetchall()]


@_op
def add_allocated(handle_id: str, blocks: list) -> bool:
    with _tx() as c:
        row = c.execute("SELECT allocated, base_version FROM handles WHERE handle_id = ?", (handle_id,)).fetchone()
        if not row:
            return False
        if row["base_version"] < 0:
            raise Gone("archivo del handle")
        allocated = json.loads(row["allocated"]) + blocks
        c.execute("UPDATE handles SET allocated = ? WHERE handle_id = ?",
                  (json.dumps(allocated), handle_id))
        return True


@_op
def commit_handle(handle_id: str, size: int, blocks: list, now: float):
    """publica de forma atómica la versión nueva del archivo desde un handle de escritura: `blocks` usa nodes=None para los bloques que no cambiaron (se toman de la versión actual), devuelve (bloques de la versión anterior, handle actualizado) y lanza Gone / Conflict / Locked"""
    with _tx() as c:
        h = c.execute("SELECT * FROM handles WHERE handle_id = ?", (handle_id,)).fetchone()
        if not h:
            raise Gone("handle")
        if h["base_version"] < 0:
            raise Gone("archivo del handle")
        f = c.execute("SELECT * FROM files WHERE path = ?", (h["path"],)).fetchone()
        if not f:
            raise Gone("archivo")
        if f["version"] != h["base_version"]:
            raise Conflict(f"versión {h['base_version']} -> {f['version']}")
        if c.execute("SELECT 1 FROM locks WHERE path = ? AND handle_id != ? LIMIT 1",
                     (h["path"], handle_id)).fetchone():
            raise Locked(h["path"])
        old_blocks = json.loads(f["blocks"])
        current = {b["block_id"]: b["nodes"] for b in old_blocks}
        for b in blocks:
            if b["nodes"] is None:
                if b["block_id"] not in current:
                    raise Conflict("bloque inexistente en la versión vigente")
                b["nodes"] = list(current[b["block_id"]])
        new_version = f["version"] + 1
        c.execute("UPDATE files SET size = ?, blocks = ?, version = ?, created_at = ? WHERE path = ?",
                  (size, json.dumps(blocks), new_version, now, h["path"]))
        c.execute("UPDATE handles SET blocks = ?, size = ?, base_version = ?, allocated = '[]'"
                  " WHERE handle_id = ?",
                  (json.dumps(blocks), size, new_version, handle_id))
        row = c.execute("SELECT * FROM handles WHERE handle_id = ?", (handle_id,)).fetchone()
        return old_blocks, json.loads(h["allocated"]), _handle_meta(row)


@_op
def refresh_handle(handle_id: str) -> dict:
    """vuelve a tomar el snapshot del handle desde la versión actual del archivo, lanza Gone si el handle o el archivo ya no existen"""
    with _tx() as c:
        h = c.execute("SELECT * FROM handles WHERE handle_id = ?", (handle_id,)).fetchone()
        if not h:
            raise Gone("handle")
        if h["base_version"] < 0:
            raise Gone("archivo del handle")
        f = c.execute("SELECT * FROM files WHERE path = ?", (h["path"],)).fetchone()
        if not f:
            raise Gone("archivo")
        c.execute("UPDATE handles SET base_version = ?, size = ?, block_size = ?, blocks = ?"
                  " WHERE handle_id = ?",
                  (f["version"], f["size"], f["block_size"], f["blocks"], handle_id))
        return _handle_meta(c.execute("SELECT * FROM handles WHERE handle_id = ?", (handle_id,)).fetchone())


def handle_block_ids() -> set:
    """bloques que alguna sesión abierta todavía necesita (snapshot + asignados sin publicar)"""
    ids = set()
    with _lock:
        rows = _conn.execute("SELECT blocks, allocated FROM handles").fetchall()
    for r in rows:
        for b in json.loads(r["blocks"]) + json.loads(r["allocated"]):
            ids.add(b["block_id"])
    return ids


def all_block_ids() -> set:
    """todos los block_id que conoce el metadato (archivos + uploads + sesiones abiertas)"""
    ids = set()
    with _lock:
        rows = _conn.execute("SELECT blocks FROM files UNION ALL SELECT blocks FROM uploads").fetchall()
    for r in rows:
        for b in json.loads(r["blocks"]):
            ids.add(b["block_id"])
    return ids | handle_block_ids()
