"""consistencia de réplicas: auto-curación de bloques corruptos, scrubber, rebalanceo y poda"""
import importlib.util
import os
import sys
import uuid

import grpc
import pytest

import dfsha_pb2
import dfsha_pb2_grpc
from conftest import NODES, ROOT, block_token, compose, datanode_channel, node_blocks, wait_until
from dfsha_client import DFShaClient

KB, MB = 1024, 1024 * 1024


def put_bytes(client, tmp_path, remote, data, block_size=64 * KB):
    p = tmp_path / ("s_" + uuid.uuid4().hex)
    p.write_bytes(data)
    client.put(str(p), remote, block_size=block_size)


def get_bytes(client, tmp_path, remote) -> bytes:
    p = tmp_path / ("d_" + uuid.uuid4().hex)
    client.get(remote, str(p))
    return p.read_bytes()


def meta(client, path):
    return client._request("GET", f"/files{path}")


def corrupt_files(node: str) -> set[str]:
    out = compose("exec", "-T", node, "sh", "-c", "ls /data 2>/dev/null | grep '\\.corrupt$' || true")
    return {line[:-8] for line in out.split() if line.endswith(".corrupt")}


# planificador del rebalanceo (puro)

@pytest.fixture(scope="module")
def app_module():
    sys.path.insert(0, str(ROOT / "control_node"))
    os.environ.setdefault("DATA_DIR", "/tmp")
    import app
    return app


def blk(i, size, nodes):
    return {"block_id": f"{i:032x}", "size": size, "nodes": list(nodes), "checksum": "0" * 64}


def test_plan_moves_levels_the_load_without_overshooting(app_module):
    used = {"a": 300 * MB, "b": 100 * MB, "c": 0}
    blocks = [("/f", blk(i, 4 * MB, ["a", "b"])) for i in range(25)]
    moves = app_module.plan_moves(used, blocks, threshold=64 * MB, max_moves=6)
    assert 0 < len(moves) <= 6
    for _path, b, src, dst in moves:
        assert src == "a" and dst == "c" and dst not in b["nodes"] and src in b["nodes"]
    assert len({m[1]["block_id"] for m in moves}) == len(moves)  # nunca el mismo bloque dos veces
    load = dict(used)
    for _p, b, src, dst in moves:
        load[src] -= b["size"]
        load[dst] += b["size"]
    assert max(load.values()) - min(load.values()) < max(used.values()) - min(used.values())


def test_plan_moves_does_nothing_when_balanced_or_nothing_fits(app_module):
    blocks = [("/f", blk(i, 4 * MB, ["a", "b"])) for i in range(5)]
    assert app_module.plan_moves({"a": 100 * MB, "b": 90 * MB, "c": 95 * MB}, blocks, 64 * MB, 4) == []
    assert app_module.plan_moves({"a": 500 * MB, "b": 0}, [("/f", blk(1, 4 * MB, ["a", "b"]))], 64 * MB, 4) == []  # b ya lo tiene
    assert app_module.plan_moves({"a": 500 * MB, "b": 0}, [("/f", blk(1, 400 * MB, ["a"]))], 64 * MB, 4) == []  # no cabe sin pasarse
    assert app_module.plan_moves({"solo": 5}, [], 1, 4) == []


# scrubber del datanode (en proceso, sin cluster)

def load_datanode(tmp_path):
    os.environ["DATA_DIR"] = str(tmp_path)
    os.environ["SCRUB_MB_PER_SEC"] = "0"
    spec = importlib.util.spec_from_file_location("datanode_server_" + uuid.uuid4().hex, ROOT / "data_node" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "data_node"))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(str(ROOT / "data_node"))
    return mod


def test_scrubber_quarantines_silently_corrupted_blocks(tmp_path):
    dn = load_datanode(tmp_path)
    good, bad = uuid.uuid4().hex, uuid.uuid4().hex
    for bid, data in ((good, b"a" * 5000), (bad, b"b" * 5000)):
        dn._store_block(bid, data, __import__("hashlib").sha256(data).hexdigest())
    raw = bytearray((tmp_path / f"{bad}.blk").read_bytes())
    raw[100] ^= 0x01  # un bit cambiado en el disco
    (tmp_path / f"{bad}.blk").write_bytes(raw)
    assert dn.scrub_once() == 1
    assert (tmp_path / f"{good}.blk").exists() and not (tmp_path / f"{bad}.blk").exists()
    assert (tmp_path / f"{bad}.corrupt").exists()
    assert dn._corrupt_report == {bad}  # se va a reportar al líder
    assert dn.scrub_once() == 0  # el sano sigue sano, el corrupto ya no se cuenta


def test_drop_replica_operation(tmp_path):
    import subprocess, textwrap
    code = textwrap.dedent("""
        import storage
        storage.init_db()
        storage.register_user('ana', 'h')
        blk = [{'block_id': 'a' * 32, 'index': 0, 'size': 1, 'nodes': ['n1', 'n2'], 'checksum': '0' * 64}]
        storage.OPS['create_empty_file'](path='/ana/f', owner='ana', block_size=4096, now=1.0)
        storage.OPS['open_handle'](handle_id='h', path='/ana/f', owner='ana', writable=True, now=1.0)
        storage.OPS['commit_handle'](handle_id='h', size=1, blocks=blk, now=2.0)
        assert storage.OPS['drop_replica'](block_id='a' * 32, node_id='n1') == ['/ana/f']
        assert storage.get_file('/ana/f')['blocks'][0]['nodes'] == ['n2']
        assert storage.OPS['drop_replica'](block_id='a' * 32, node_id='n1') == []      # idempotente
        assert storage.OPS['drop_replica'](block_id='b' * 32, node_id='n2') == []      # bloque desconocido
        print('ok')
    """)
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT / "control_node", capture_output=True, text=True)
    assert r.returncode == 0 and "ok" in r.stdout, r.stdout + r.stderr


# auto-curación en el cluster

def test_corrupt_replica_is_quarantined_and_replaced_by_a_healthy_copy(cluster_up, user, tmp_path):
    p = f"{user.home}/heal.bin"
    data = os.urandom(300 * KB)
    put_bytes(user, tmp_path, p, data)
    b = meta(user, p)["blocks"][0]
    bad_node = f"datanode{b['replicas'][0][-1]}"
    bid, port = b["block_id"], 6000 + int(bad_node[-1])
    compose("exec", "-T", bad_node, "python", "-c",
            f"p='/data/{bid}.blk'; b=bytearray(open(p,'rb').read()); b[40]^=0xFF; open(p,'wb').write(b)")

    # una lectura directa a esa réplica la descubre: el datanode la aparta y avisa al líder
    with pytest.raises(grpc.RpcError) as e:
        dfsha_pb2_grpc.DataNodeStub(datanode_channel(port)).ReadBlock(
            dfsha_pb2.BlockId(block_id=bid), metadata=(("x-dfsha-token", block_token(bid, "r")),), timeout=5)
    assert e.value.code() == grpc.StatusCode.DATA_LOSS
    assert bid in corrupt_files(bad_node)

    def healthy_again():
        copies = [n for n in NODES if bid in node_blocks(n)]
        return len(copies) == 2 and len(meta(user, p)["blocks"][0]["replicas"]) == 2
    wait_until(healthy_again, 90, "el líder repone la réplica sana", interval=3)
    assert get_bytes(user, tmp_path, p) == data


# ampliar el cluster: un datanode nuevo (vacío) recibe bloques

@pytest.mark.slow
def test_new_datanode_gets_blocks_through_rebalancing(cluster_up, user, tmp_path):
    p = f"{user.home}/grande.bin"
    data = os.urandom(150 * MB)  # 300 mb repartidos en 3 nodos: unos 100 mb por nodo
    put_bytes(user, tmp_path, p, data, block_size=4 * MB)
    try:
        compose("--profile", "extra", "up", "-d", "datanode4")
        wait_until(lambda: DFShaClient()._request("GET", "/health")["datanodes_alivos"] == 4, 60, "el cuarto DataNode se une")
        ids = {b["block_id"] for b in meta(user, p)["blocks"]}
        wait_until(lambda: len(node_blocks("datanode4") & ids) >= 3, 150,
                   "el rebalanceo mueve bloques al nodo nuevo", interval=5)
        # el factor de replicación se mantiene durante y después de los movimientos
        wait_until(lambda: all(len(b["replicas"]) >= 2 for b in meta(user, p)["blocks"]), 60, "RF intacto")
        assert get_bytes(user, tmp_path, p) == data
    finally:
        compose("--profile", "extra", "rm", "-sf", "datanode4", check=False)
        import subprocess
        project = os.environ.get("COMPOSE_PROJECT_NAME", ROOT.name.lower())
        subprocess.run(["docker", "volume", "rm", f"{project}_datanode4_data"], capture_output=True)
        user.rm(p)
