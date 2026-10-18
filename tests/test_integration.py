import os
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import NODES, compose, node_blocks, wait_until, sha
from dfsha_client import DFShaClient, DFShaError

pytestmark = pytest.mark.usefixtures("cluster_up")

KB = 1024
MB = 1024 * 1024


def put_bytes(client: DFShaClient, workdir, remote: str, data: bytes, block_size=None) -> dict:
    p = workdir / ("src_" + uuid.uuid4().hex)
    p.write_bytes(data)
    return client.put(str(p), remote, block_size=block_size)


def get_bytes(client: DFShaClient, workdir, remote: str) -> bytes:
    p = workdir / ("dst_" + uuid.uuid4().hex)
    client.get(remote, str(p))
    return p.read_bytes()


def file_meta(client: DFShaClient, remote: str) -> dict:
    return client._request("GET", f"/files{remote}")


def addr_node(addr: str) -> str:  # localhost:6002 -> datanode2
    return f"datanode{addr[-1]}"


# transferencia, partición y distribución

def test_roundtrip_multiblock_and_distribution(user, workdir):
    data = os.urandom(5 * MB)
    user.mkdir(f"{user.home}/d1")
    put_bytes(user, workdir, f"{user.home}/d1/f.bin", data, block_size=256 * KB)
    assert get_bytes(user, workdir, f"{user.home}/d1/f.bin") == data

    meta = file_meta(user, f"{user.home}/d1/f.bin")
    assert len(meta["blocks"]) == 20
    per_node = {n: 0 for n in NODES}
    for b in meta["blocks"]:
        assert len(b["replicas"]) == 2
        for a in b["replicas"]:
            per_node[addr_node(a)] += 1
    # el archivo queda repartido entre varios nodos (con cargas muy distintas el balanceo puede dejar uno afuera, el reparto parejo se prueba en test_placement.py)
    used = [n for n, c in per_node.items() if c > 0]
    assert len(used) >= 2, per_node


@pytest.mark.parametrize("size", [0, 1, 64 * KB, 64 * KB + 1])
def test_edge_sizes(user, workdir, size):
    data = os.urandom(size)
    put_bytes(user, workdir, f"{user.home}/e.bin", data, block_size=64 * KB)
    assert get_bytes(user, workdir, f"{user.home}/e.bin") == data


# namespace y control de acceso

def test_directories(user):
    h = user.home
    assert user.ls("/")["dirs"] == [h]  # cada usuario solo ve su propio home en la raíz
    user.mkdir(f"{h}/a")
    user.mkdir(f"{h}/a/b")
    assert user.ls(h)["dirs"] == [f"{h}/a"]
    assert user.ls(f"{h}/a")["dirs"] == [f"{h}/a/b"]
    with pytest.raises(DFShaError, match="404"):
        user.mkdir(f"{h}/nope/x")  # el padre tiene que existir
    with pytest.raises(DFShaError, match="409"):
        user.rmdir(f"{h}/a")  # no vacío
    user.rmdir(f"{h}/a/b")
    user.rmdir(f"{h}/a")
    with pytest.raises(DFShaError, match="404"):
        user.ls(f"{h}/a")
    with pytest.raises(DFShaError, match="400"):
        user.mkdir("relativo")  # los paths son absolutos


def test_user_isolation(make_user, workdir):
    alice, bob = make_user(), make_user()
    ah = alice.home
    alice.mkdir(f"{ah}/priv")
    put_bytes(alice, workdir, f"{ah}/priv/s.txt", b"secreto")

    assert bob.ls("/")["dirs"] == [bob.home]  # bob no ve el home de alice
    for call in (lambda: bob.ls(f"{ah}/priv"),
                 lambda: bob.mkdir(f"{ah}/priv/x"),
                 lambda: bob.rm(f"{ah}/priv/s.txt"),
                 lambda: bob.get(f"{ah}/priv/s.txt", str(workdir / "x")),
                 lambda: put_bytes(bob, workdir, f"{ah}/priv/s.txt", b"pisado"),
                 lambda: bob.rmdir(f"{ah}/priv"),
                 lambda: bob.rmdir(ah)):
        with pytest.raises(DFShaError, match="403"):
            call()
    with pytest.raises(DFShaError, match="409"):
        bob.mkdir(ah)  # mismo nombre, otro dueño
    with pytest.raises(DFShaError, match="409"):
        bob.register(alice.username, "otraclave123")  # el usuario ya existe
    assert get_bytes(alice, workdir, f"{ah}/priv/s.txt") == b"secreto"


def test_token_required():
    with pytest.raises(DFShaError, match="401"):
        DFShaClient().ls("/")
    with pytest.raises(DFShaError, match="401"):
        DFShaClient().login("nadie", "nada123")


# consistencia: borrado, reemplazo (copy-on-write), concurrencia

def _all_blocks() -> set[str]:
    out = set()
    for n in NODES:
        out |= node_blocks(n)
    return out


def test_rm_frees_physical_blocks(user, workdir):
    put_bytes(user, workdir, f"{user.home}/r.bin", os.urandom(600 * KB), block_size=128 * KB)
    ids = {b["block_id"] for b in file_meta(user, f"{user.home}/r.bin")["blocks"]}
    assert ids <= _all_blocks()
    user.rm(f"{user.home}/r.bin")
    assert not (ids & _all_blocks())
    with pytest.raises(DFShaError, match="404"):
        user.get(f"{user.home}/r.bin", str(workdir / "x"))


def test_overwrite_is_atomic_and_frees_old_version(user, workdir):
    put_bytes(user, workdir, f"{user.home}/v.bin", b"A" * 300 * KB, block_size=128 * KB)
    old_ids = {b["block_id"] for b in file_meta(user, f"{user.home}/v.bin")["blocks"]}
    put_bytes(user, workdir, f"{user.home}/v.bin", b"B" * 200 * KB, block_size=128 * KB)
    assert get_bytes(user, workdir, f"{user.home}/v.bin") == b"B" * 200 * KB
    assert not (old_ids & _all_blocks())


def test_failed_upload_leaves_no_ghost_file(user, workdir):
    data_path = workdir / "x.bin"
    data_path.write_bytes(b"x" * 100)
    plan = user._request("POST", "/files/init", json={"path": f"{user.home}/ghost.bin", "size": 100})
    assert user.ls(user.home)["files"] == []  # un upload a medias no se ve
    user._request("POST", "/files/abort", json={"upload_id": plan["upload_id"]})
    with pytest.raises(DFShaError, match="404"):
        user.get(f"{user.home}/ghost.bin", str(workdir / "y"))


def test_concurrent_uploads_distinct_files(user, workdir):
    payloads = {f"{user.home}/c{i}.bin": os.urandom(700 * KB) for i in range(8)}
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda kv: put_bytes(user, workdir, kv[0], kv[1], block_size=128 * KB), payloads.items()))
    with ThreadPoolExecutor(8) as pool:
        got = list(pool.map(lambda p: (p, get_bytes(user, workdir, p)), payloads))
    for path, data in got:
        assert sha(data) == sha(payloads[path]), path


def test_concurrent_writers_same_path_never_mix(user, workdir):
    """last-writer-wins a nivel de archivo: el resultado es exactamente una de las versiones"""
    versions = [bytes([65 + i]) * (500 * KB) for i in range(5)]
    barrier = threading.Barrier(len(versions))

    def writer(v):
        barrier.wait()
        put_bytes(user, workdir, f"{user.home}/same.bin", v, block_size=128 * KB)

    with ThreadPoolExecutor(len(versions)) as pool:
        list(pool.map(writer, versions))
    assert get_bytes(user, workdir, f"{user.home}/same.bin") in versions


def test_concurrent_readers(user, workdir):
    data = os.urandom(2 * MB)
    put_bytes(user, workdir, f"{user.home}/rd.bin", data, block_size=128 * KB)
    with ThreadPoolExecutor(10) as pool:
        outs = list(pool.map(lambda _: get_bytes(user, workdir, f"{user.home}/rd.bin"), range(10)))
    assert all(o == data for o in outs)


# integridad: corrupción silenciosa en disco

def _corrupt(node: str, block_id: str):
    compose("exec", "-T", node, "python", "-c",
            f"p='/data/{block_id}.blk'; b=bytearray(open(p,'rb').read()); b[-1]^=0xFF; open(p,'wb').write(b)")


def test_corrupted_replica_is_detected_and_skipped(user, workdir):
    data = os.urandom(300 * KB)
    put_bytes(user, workdir, f"{user.home}/cor.bin", data, block_size=128 * KB)
    meta = file_meta(user, f"{user.home}/cor.bin")
    first = meta["blocks"][0]
    _corrupt(addr_node(first["replicas"][0]), first["block_id"])
    assert get_bytes(user, workdir, f"{user.home}/cor.bin") == data  # lee de la réplica sana
    _corrupt(addr_node(first["replicas"][1]), first["block_id"])
    with pytest.raises(DFShaError, match="ilegible"):  # ya no hay réplica sana
        user.get(f"{user.home}/cor.bin", str(workdir / "nope"))


# tolerancia a fallos de los datanodes (lentas: esperan al monitor)

@pytest.fixture
def stop_node():
    stopped = []

    def _stop(n):
        compose("stop", n)
        stopped.append(n)

    yield _stop
    for n in stopped:
        compose("start", n)


def _replica_counts(client, path):
    return [len(b["replicas"]) for b in file_meta(client, path)["blocks"]]


def _alive_count():
    try:
        return DFShaClient()._request("GET", "/health")["datanodes_alivos"]
    except DFShaError:
        return 0  # el control node todavía está arrancando


def _physical_copies(block_ids: set[str]) -> dict[str, int]:
    held = {n: node_blocks(n) for n in NODES}
    return {b: sum(b in held[n] for n in NODES) for b in block_ids}


@pytest.mark.slow
def test_datanode_failure_read_failover_and_rereplication(user, workdir, stop_node):
    path = f"{user.home}/ha.bin"
    data = os.urandom(3 * MB)
    put_bytes(user, workdir, path, data, block_size=256 * KB)
    ids = {b["block_id"] for b in file_meta(user, path)["blocks"]}
    assert set(_replica_counts(user, path)) == {2}

    stop_node("datanode3")
    wait_until(lambda: _alive_count() == 2, 40, "datanode3 declarado caído")
    # se perdieron réplicas: algunos bloques solo quedan en 1 nodo vivo
    assert 1 in _replica_counts(user, path)
    # 1) la lectura sigue funcionando de una vez (failover entre réplicas)
    assert get_bytes(user, workdir, path) == data
    # 2) el monitor repone el factor de replicación en los 2 nodos que quedan
    wait_until(lambda: set(_replica_counts(user, path)) == {2}, 150, "re-replicación a RF=2")
    held = {n: node_blocks(n) for n in ("datanode1", "datanode2")}
    assert ids <= held["datanode1"] and ids <= held["datanode2"]  # físicamente en los dos
    assert get_bytes(user, workdir, path) == data

    # 3) escribir con un nodo caído sigue funcionando con rf completo (2 vivos)
    path2 = f"{user.home}/ha2.bin"
    put_bytes(user, workdir, path2, data, block_size=256 * KB)
    assert get_bytes(user, workdir, path2) == data

    # 4) cuando vuelve el nodo (con sus bloques viejos en disco) se recorta el exceso hasta rf
    compose("start", "datanode3")
    wait_until(lambda: _alive_count() == 3, 40, "datanode3 de vuelta")
    wait_until(lambda: set(_physical_copies(ids).values()) == {2}, 150,
               "recorte de réplicas sobrantes", interval=5)
    assert get_bytes(user, workdir, path) == data


@pytest.mark.slow
def test_degraded_write_with_single_node_then_heals(user, workdir, stop_node):
    stop_node("datanode2")
    stop_node("datanode3")
    wait_until(lambda: _alive_count() == 1, 40, "solo 1 nodo vivo")
    path = f"{user.home}/deg.bin"
    data = os.urandom(600 * KB)
    res = put_bytes(user, workdir, path, data, block_size=128 * KB)
    assert res["under_replicated_blocks"] > 0  # escritura degradada (rf efectivo 1)
    assert get_bytes(user, workdir, path) == data
    ids = {b["block_id"] for b in file_meta(user, path)["blocks"]}

    compose("start", "datanode2")
    compose("start", "datanode3")
    wait_until(lambda: _alive_count() == 3, 40, "los 3 nodos de vuelta")
    wait_until(lambda: set(_physical_copies(ids).values()) == {2}, 180, "sanación a RF=2", interval=5)
    assert get_bytes(user, workdir, path) == data


@pytest.mark.slow
def test_orphan_blocks_are_garbage_collected(user):
    """un bloque que ningún archivo usa (por ejemplo restos de un borrado con el nodo caído) lo detecta el reporte de bloques y lo borra el propio datanode"""
    import hashlib, dfsha_pb2, dfsha_pb2_grpc
    from conftest import datanode_channel, block_token
    orphan = uuid.uuid4().hex
    data = os.urandom(1000)
    ack = dfsha_pb2_grpc.DataNodeStub(datanode_channel(6001)).WriteBlock(
        dfsha_pb2.Block(block_id=orphan, data=data, checksum=hashlib.sha256(data).hexdigest()),
        metadata=(("x-dfsha-token", block_token(orphan, "w")),))
    assert ack.success and orphan in node_blocks("datanode1")
    wait_until(lambda: orphan not in node_blocks("datanode1"), 180, "GC del bloque huérfano", interval=5)


def internal_call(node: str, block_id: str, op: str, expect_node: str, with_cert: bool = True) -> str:
    """llama a DeleteBlock en el puerto interno (mtls) de un datanode desde dentro de su propio contenedor (ese puerto no se publica al host), devuelve 'OK' o el código grpc del error"""
    code = f"""
import os, grpc, dfsha_pb2, dfsha_pb2_grpc, dfsha_security as sec
keys = sec.Keys(os.environ.get('CLUSTER_SECRET'))
ca = open(os.environ['TLS_CA'], 'rb').read()
kw = dict(root_certificates=ca)
if {with_cert!r}:
    kw.update(private_key=open(os.environ['TLS_KEY'], 'rb').read(), certificate_chain=open(os.environ['TLS_CERT'], 'rb').read())
ch = grpc.secure_channel('localhost:6100', grpc.ssl_channel_credentials(**kw))
try:
    dfsha_pb2_grpc.DataNodeStub(ch).DeleteBlock(dfsha_pb2.BlockId(block_id={block_id!r}), timeout=5,
        metadata=(('x-dfsha-token', sec.make_block_token(keys, {block_id!r}, {op!r}, 60)), ('x-dfsha-expect-node', {expect_node!r})))
    print('OK')
except grpc.RpcError as e:
    print(e.code().name)
"""
    return compose("exec", "-T", node, "python", "-c", code).strip().splitlines()[-1]


def test_datanode_refuses_calls_meant_for_another_node(user, workdir):
    """una ip reasignada al reiniciar un contenedor no debe hacer que un borrado llegue al nodo equivocado"""
    p = f"{user.home}/ident.bin"
    put_bytes(user, workdir, p, os.urandom(1000))
    block = file_meta(user, p)["blocks"][0]
    holder = addr_node(block["replicas"][0])
    assert internal_call(holder, block["block_id"], "d", "otro-nodo") == "FAILED_PRECONDITION"
    assert block["block_id"] in node_blocks(holder)  # no se borró
    assert get_bytes(user, workdir, p)


@pytest.mark.slow
def test_deletes_still_reach_the_right_node_after_containers_swap_ips(user, workdir):
    warm = f"{user.home}/warm.bin"
    put_bytes(user, workdir, warm, os.urandom(300 * KB), block_size=64 * KB)
    user.rm(warm)  # el líder abre (y guarda) canales a los datanodes
    compose("stop", "datanode2", "datanode3")
    compose("start", "datanode3")  # arrancar en orden inverso suele intercambiar sus ips
    compose("start", "datanode2")
    wait_until(lambda: DFShaClient()._request("GET", "/health")["datanodes_alivos"] == 3, 60, "3 DataNodes de vuelta")
    for i in range(3):
        p = f"{user.home}/swap{i}.bin"
        put_bytes(user, workdir, p, os.urandom(400 * KB), block_size=64 * KB)
        ids = {b["block_id"] for b in file_meta(user, p)["blocks"]}
        user.rm(p)
        wait_until(lambda: not (ids & _all_blocks()), 20, f"bloques de swap{i} borrados de los 3 nodos", interval=1)
