"""
Cliente DFSha: CLI que habla REST con el ControlNode (metadatos, gestión del
fs) y gRPC directo con los DataNodes (transferencia real de bloques).

Uso:
    python cli.py register <user> <pass>
    python cli.py login <user> <pass>
    python cli.py put <archivo_local> <path_remoto>
    python cli.py get <path_remoto> <archivo_local>
    python cli.py ls [path]
    python cli.py mkdir <path>
    python cli.py rm <path>
"""
import os
import sys
import json
import hashlib

import grpc
import requests

import dfsha_pb2
import dfsha_pb2_grpc

CONTROL_NODE_URL = os.environ.get("CONTROL_NODE_URL", "http://localhost:8000")
TOKEN_FILE = os.path.expanduser("~/.dfsha_token")


def _headers():
    if not os.path.exists(TOKEN_FILE):
        print("No hay sesión. Corre: python cli.py login <user> <pass>")
        sys.exit(1)
    with open(TOKEN_FILE) as f:
        token = f.read().strip()
    return {"Authorization": f"Bearer {token}"}


def cmd_register(user, password):
    r = requests.post(f"{CONTROL_NODE_URL}/auth/register", json={"username": user, "password": password})
    r.raise_for_status()
    print("Usuario creado. Ahora podés hacer login.")


def cmd_login(user, password):
    r = requests.post(f"{CONTROL_NODE_URL}/auth/login", json={"username": user, "password": password})
    r.raise_for_status()
    token = r.json()["token"]
    with open(TOKEN_FILE, "w") as f:
        f.write(token)
    print("Login OK")


def cmd_mkdir(path):
    r = requests.post(f"{CONTROL_NODE_URL}/mkdir", json={"path": path}, headers=_headers())
    r.raise_for_status()
    print("OK")


def cmd_ls(path="/"):
    r = requests.get(f"{CONTROL_NODE_URL}/ls", params={"path": path}, headers=_headers())
    r.raise_for_status()
    data = r.json()
    for d in data["dirs"]:
        print(f"[dir]  {d}")
    for f in data["files"]:
        print(f"[file] {f['path']}  ({f['size']} bytes, {f['status']})")


def cmd_rm(path):
    r = requests.post(f"{CONTROL_NODE_URL}/rm", json={"path": path}, headers=_headers())
    r.raise_for_status()
    print("OK")


def _write_block_to_replicas(block_id: str, data: bytes, replicas: list[str]):
    checksum = hashlib.sha256(data).hexdigest()
    ok_count = 0
    for addr in replicas:
        try:
            with grpc.insecure_channel(addr) as channel:
                stub = dfsha_pb2_grpc.DataNodeStub(channel)
                ack = stub.WriteBlock(
                    dfsha_pb2.Block(block_id=block_id, data=data, checksum=checksum),
                    timeout=10,
                )
                if ack.success:
                    ok_count += 1
                else:
                    print(f"  aviso: {addr} rechazó el bloque: {ack.message}")
        except grpc.RpcError as e:
            print(f"  aviso: no se pudo escribir en {addr}: {e.details()}")
    if ok_count == 0:
        raise RuntimeError(f"bloque {block_id} no se pudo escribir en ninguna réplica")
    return ok_count


def cmd_put(local_path, remote_path):
    size = os.path.getsize(local_path)
    r = requests.post(
        f"{CONTROL_NODE_URL}/files/init",
        json={"path": remote_path, "size": size},
        headers=_headers(),
    )
    r.raise_for_status()
    plan = r.json()
    blocks = plan["blocks"]
    block_size = size // len(blocks) + 1 if blocks else size

    with open(local_path, "rb") as f:
        for b in blocks:
            chunk = f.read(4 * 1024 * 1024)
            ok = _write_block_to_replicas(b["block_id"], chunk, b["replicas"])
            print(f"bloque {b['index']}: escrito en {ok}/{len(b['replicas'])} réplicas")

    r = requests.post(f"{CONTROL_NODE_URL}/files/complete", json={"path": remote_path}, headers=_headers())
    r.raise_for_status()
    print(f"Subido: {remote_path}")


def _read_block_from_replicas(block_id: str, replicas: list[str]) -> bytes:
    last_error = None
    for addr in replicas:
        try:
            with grpc.insecure_channel(addr) as channel:
                stub = dfsha_pb2_grpc.DataNodeStub(channel)
                block = stub.ReadBlock(dfsha_pb2.BlockId(block_id=block_id), timeout=10)
                if block.checksum and block.checksum != hashlib.sha256(block.data).hexdigest():
                    raise RuntimeError("checksum no coincide")
                return block.data
        except Exception as e:
            last_error = e
            continue
    raise RuntimeError(f"no se pudo leer el bloque {block_id} de ninguna réplica: {last_error}")


def cmd_get(remote_path, local_path):
    r = requests.get(f"{CONTROL_NODE_URL}/files{remote_path}", headers=_headers())
    r.raise_for_status()
    meta = r.json()

    with open(local_path, "wb") as out:
        for b in sorted(meta["blocks"], key=lambda x: x["index"]):
            data = _read_block_from_replicas(b["block_id"], b["replicas"])
            out.write(data)
    print(f"Descargado: {local_path}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd, args = sys.argv[1], sys.argv[2:]
    try:
        if cmd == "register":
            cmd_register(args[0], args[1])
        elif cmd == "login":
            cmd_login(args[0], args[1])
        elif cmd == "put":
            cmd_put(args[0], args[1])
        elif cmd == "get":
            cmd_get(args[0], args[1])
        elif cmd == "ls":
            cmd_ls(args[0] if args else "/")
        elif cmd == "mkdir":
            cmd_mkdir(args[0])
        elif cmd == "rm":
            cmd_rm(args[0])
        else:
            print(__doc__)
    except requests.HTTPError as e:
        print(f"Error del ControlNode: {e.response.status_code} {e.response.text}")
        sys.exit(1)


if __name__ == "__main__":
    main()
