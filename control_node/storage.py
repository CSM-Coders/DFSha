"""
Capa de persistencia del ControlNode. Todo lo que antes vivía en dicts/sets
en memoria (usuarios, directorios, archivos y sus bloques) ahora vive en
SQLite, en un archivo montado en un volumen Docker. Así el ControlNode puede
reiniciarse o caerse sin perder el árbol de archivos ni las cuentas.

Lo que sigue siendo efímero a propósito:
- TOKENS de sesión: si el ControlNode se reinicia, hay que loguearse otra
  vez. Es una decisión simple, no una limitación grave.
- DATANODES registrados: se repueblan solos en segundos vía heartbeat.
"""
import os
import json
import sqlite3
import threading

DB_PATH = os.environ.get("DB_PATH", "/data/dfsha.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

_lock = threading.Lock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row


def init_db():
    with _lock:
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "  username TEXT PRIMARY KEY,"
            "  password_hash TEXT NOT NULL"
            ")"
        )
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS dirs ("
            "  path TEXT PRIMARY KEY"
            ")"
        )
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS files ("
            "  path TEXT PRIMARY KEY,"
            "  size INTEGER NOT NULL,"
            "  block_size INTEGER NOT NULL,"
            "  blocks TEXT NOT NULL,"  # JSON
            "  status TEXT NOT NULL,"
            "  owner TEXT NOT NULL"
            ")"
        )
        _conn.execute("INSERT OR IGNORE INTO dirs (path) VALUES ('/')")
        _conn.commit()


def seed_user(username: str, password_hash: str):
    with _lock:
        _conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        _conn.commit()


# --- usuarios --------------------------------------------------------------

def get_user_hash(username: str):
    row = _conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row["password_hash"] if row else None


def create_user(username: str, password_hash: str) -> bool:
    """Devuelve False si el usuario ya existía (no lo sobreescribe)."""
    with _lock:
        cur = _conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        _conn.commit()
        return cur.rowcount > 0


# --- directorios -------------------------------------------------------------

def add_dir(path: str):
    with _lock:
        _conn.execute("INSERT OR IGNORE INTO dirs (path) VALUES (?)", (path,))
        _conn.commit()


def remove_dir(path: str):
    with _lock:
        _conn.execute("DELETE FROM dirs WHERE path = ?", (path,))
        _conn.commit()


def list_dirs():
    return [r["path"] for r in _conn.execute("SELECT path FROM dirs").fetchall()]


def has_children(prefix: str) -> bool:
    """True si hay algún archivo o subdirectorio bajo prefix/."""
    f = _conn.execute(
        "SELECT 1 FROM files WHERE path LIKE ? LIMIT 1", (prefix + "/%",)
    ).fetchone()
    if f:
        return True
    d = _conn.execute(
        "SELECT 1 FROM dirs WHERE path LIKE ? AND path != ? LIMIT 1", (prefix + "/%", prefix)
    ).fetchone()
    return d is not None


# --- archivos ----------------------------------------------------------------

def _row_to_meta(row) -> dict:
    return {
        "size": row["size"],
        "block_size": row["block_size"],
        "blocks": json.loads(row["blocks"]),
        "status": row["status"],
        "owner": row["owner"],
    }


def list_files() -> dict:
    rows = _conn.execute(
        "SELECT path, size, block_size, blocks, status, owner FROM files"
    ).fetchall()
    return {r["path"]: _row_to_meta(r) for r in rows}


def get_file(path: str):
    row = _conn.execute(
        "SELECT size, block_size, blocks, status, owner FROM files WHERE path = ?",
        (path,),
    ).fetchone()
    return _row_to_meta(row) if row else None


def save_file(path: str, meta: dict):
    with _lock:
        _conn.execute(
            "INSERT INTO files (path, size, block_size, blocks, status, owner) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(path) DO UPDATE SET "
            "  size=excluded.size, block_size=excluded.block_size, "
            "  blocks=excluded.blocks, status=excluded.status, owner=excluded.owner",
            (
                path,
                meta["size"],
                meta["block_size"],
                json.dumps(meta["blocks"]),
                meta["status"],
                meta["owner"],
            ),
        )
        _conn.commit()


def update_file_status(path: str, status: str):
    with _lock:
        _conn.execute("UPDATE files SET status = ? WHERE path = ?", (status, path))
        _conn.commit()


def delete_file(path: str):
    with _lock:
        _conn.execute("DELETE FROM files WHERE path = ?", (path,))
        _conn.commit()
