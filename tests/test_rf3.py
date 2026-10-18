"""rf3: acceso tipo archivo (open/read/write/seek/truncate/close/lock) contra el cluster"""
import os
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import NODES, node_blocks, wait_until
from dfsha_client import DFShaError

pytestmark = pytest.mark.usefixtures("cluster_up")

KB = 1024
BS = 64 * KB  # tamaño de bloque pequeño para tener muchos bloques con poco dato


def block_ids(client, path):
    return [b["block_id"] for b in client._request("GET", f"/files{path}")["blocks"]]


def make_file(client, path, data: bytes, bs=BS):
    with client.open(path, "w", block_size=bs) as f:
        f.write(data)


def read_all(client, path) -> bytes:
    with client.open(path, "r") as f:
        return f.read()


# básico

def test_create_write_read_back_and_interop_with_get(user, workdir):
    p = f"{user.home}/a.bin"
    data = os.urandom(300 * KB)
    with user.open(p, "w", block_size=BS) as f:
        assert f.write(data[:100 * KB]) == 100 * KB
        assert f.tell() == 100 * KB
        f.write(data[100 * KB:])
    assert read_all(user, p) == data
    out = workdir / "o.bin"
    user.get(p, str(out))  # la api de transferencia ve el mismo archivo
    assert out.read_bytes() == data
    assert user.stat(p)["size"] == len(data)


def test_read_your_writes_before_close(user):
    p = f"{user.home}/ryw.bin"
    with user.open(p, "w+", block_size=BS) as f:
        f.write(b"hola mundo")
        f.seek(0)
        assert f.read() == b"hola mundo"
        f.seek(5)
        f.write(b"MUNDO")
        f.seek(0)
        assert f.read() == b"hola MUNDO"
        # nadie más ve los cambios hasta el commit
        assert user.stat(p)["size"] == 0
    assert read_all(user, p) == b"hola MUNDO"


def test_modes_and_errors(user):
    p = f"{user.home}/m.bin"
    with pytest.raises(DFShaError, match="404"):
        user.open(p, "r")
    with pytest.raises(DFShaError, match="404"):
        user.open(p, "r+")
    with user.open(p, "w") as f:
        f.write(b"abc")
        with pytest.raises(IOError):
            f.read()  # 'w' no lee
    with user.open(p, "r") as f:
        with pytest.raises(IOError):
            f.write(b"x")  # 'r' no escribe
    with pytest.raises(ValueError):
        user.open(p, "rb")
    with pytest.raises(DFShaError, match="409"):
        user.open(user.home, "r")  # es un directorio
    f = user.open(p, "r")
    f.close()
    with pytest.raises(ValueError):
        f.read()


def test_append_mode(user):
    p = f"{user.home}/ap.log"
    with user.open(p, "w", block_size=BS) as f:
        f.write(b"A" * (BS - 10))
    with user.open(p, "a") as f:
        f.write(b"B" * 30)  # cruza el límite de bloque
        f.seek(0)
        f.write(b"C" * 5)  # en modo append siempre va al final
    with user.open(p, "a") as f:
        f.write(b"D")
    assert read_all(user, p) == b"A" * (BS - 10) + b"B" * 30 + b"C" * 5 + b"D"


def test_w_truncates_existing_and_r_plus_does_not(user):
    p = f"{user.home}/t.bin"
    make_file(user, p, b"x" * 1000)
    with user.open(p, "r+") as f:
        f.write(b"Y")
    assert read_all(user, p) == b"Y" + b"x" * 999
    with user.open(p, "w") as f:
        pass
    assert read_all(user, p) == b""
    assert user.stat(p)["size"] == 0


# rangos, bloques parciales y copy-on-write

def test_range_reads_across_block_boundaries(user):
    p = f"{user.home}/r.bin"
    data = os.urandom(5 * BS + 1234)
    make_file(user, p, data)
    rng = random.Random(7)
    with user.open(p, "r") as f:
        for _ in range(40):
            off = rng.randrange(0, len(data) + 100)
            n = rng.randrange(0, 3 * BS)
            f.seek(off)
            assert f.read(n) == data[off:off + n], (off, n)
        f.seek(-10, 2)
        assert f.read() == data[-10:]


def test_partial_update_rewrites_only_touched_blocks(user):
    p = f"{user.home}/cow.bin"
    data = bytearray(os.urandom(8 * BS))
    make_file(user, p, bytes(data))
    before = block_ids(user, p)
    with user.open(p, "r+") as f:
        f.seek(3 * BS + 100)
        f.write(b"PARCHE")  # toca solo el bloque 3
    after = block_ids(user, p)
    data[3 * BS + 100:3 * BS + 106] = b"PARCHE"
    assert read_all(user, p) == bytes(data)
    assert [i for i, (a, b) in enumerate(zip(before, after)) if a != b] == [3]
    assert user.stat(p)["version"] == 3  # v1 al crear, v2 al escribir los datos, v3 con el parche
    # el bloque 3 anterior ya no lo usa nadie: se libera del disco
    wait_until(lambda: before[3] not in set().union(*(node_blocks(n) for n in NODES)), 10, "bloque viejo liberado")


def test_write_beyond_eof_zero_fills(user):
    p = f"{user.home}/hole.bin"
    with user.open(p, "w", block_size=BS) as f:
        f.write(b"ini")
        f.seek(3 * BS + 10)
        f.write(b"fin")
    expected = b"ini" + bytes(3 * BS + 10 - 3) + b"fin"
    assert read_all(user, p) == expected
    assert user.stat(p)["size"] == len(expected)


def test_truncate_shrink_then_grow_never_resurrects_old_bytes(user):
    p = f"{user.home}/tr.bin"
    make_file(user, p, b"Z" * (3 * BS))
    with user.open(p, "r+") as f:
        f.truncate(BS + 5)
        f.truncate(2 * BS + 7)  # crece otra vez: lo nuevo tiene que ser ceros
        f.seek(0)
        assert f.read() == b"Z" * (BS + 5) + bytes(BS + 2)
    assert read_all(user, p) == b"Z" * (BS + 5) + bytes(BS + 2)
    with user.open(p, "r+") as f:
        f.truncate(0)
    assert read_all(user, p) == b""


def test_large_unflushed_session_stages_blocks(user, monkeypatch):
    """con poca memoria para bloques sucios, el cliente los va mandando a los datanodes (sin publicar) y el resultado final es igual"""
    from dfsha_client import DFShaFile
    monkeypatch.setattr(DFShaFile, "MAX_DIRTY_BYTES", 2 * BS)
    p = f"{user.home}/big.bin"
    data = os.urandom(20 * BS + 17)
    with user.open(p, "w", block_size=BS) as f:
        for i in range(0, len(data), 7000):
            f.write(data[i:i + 7000])
        assert len(f._staged) > 0  # ya hubo envíos intermedios
        assert user.stat(p)["size"] == 0  # y aun así nada se ve
    assert read_all(user, p) == data


@pytest.mark.parametrize("seed", [1234, 1, 2, 3, 4, 5, 6, 7])
def test_model_based_fuzz(user, seed):
    """operaciones aleatorias (write/truncate/seek/read/flush) contra un modelo en memoria"""
    rng = random.Random(seed)
    p = f"{user.home}/fuzz{seed}.bin"
    model = bytearray()
    with user.open(p, "w+", block_size=BS) as f:
        pos = 0
        for step in range(80):
            op = rng.choice(["write", "write", "write", "truncate", "seek", "read", "flush"])
            if op == "write":
                data = os.urandom(rng.choice([1, 100, BS - 1, BS, BS + 1, 3 * BS]))
                f.write(data)
                if pos > len(model):
                    model.extend(bytes(pos - len(model)))
                model[pos:pos + len(data)] = data
                pos += len(data)
            elif op == "truncate":
                size = rng.randrange(0, len(model) + 2 * BS)
                f.truncate(size)
                if size < len(model):
                    del model[size:]
                else:
                    model.extend(bytes(size - len(model)))
            elif op == "seek":
                pos = rng.randrange(0, len(model) + BS)
                f.seek(pos)
            elif op == "read":
                n = rng.randrange(0, 2 * BS)
                assert f.read(n) == bytes(model[pos:pos + n]), step
                pos = min(len(model), pos + n) if pos < len(model) else pos
            else:
                f.flush()
            assert f.size == len(model), (step, op)
        f.seek(0)
        assert f.read() == bytes(model)
    assert read_all(user, p) == bytes(model)


# sesiones: snapshot, conflictos y permisos

def test_reader_keeps_snapshot_while_writer_publishes(user):
    p = f"{user.home}/snap.bin"
    make_file(user, p, b"v1" * BS)
    reader = user.open(p, "r")
    with user.open(p, "w") as w:
        w.write(b"v2-nuevo")
    assert read_all(user, p) == b"v2-nuevo"  # una sesión nueva ve la versión nueva
    assert reader.read() == b"v1" * BS  # el lector viejo sigue viendo su snapshot completo
    reader.close()


def test_optimistic_conflict_second_writer_loses(make_user):
    c = make_user()
    p = f"{c.home}/conf.bin"
    make_file(c, p, b"base" * 100)
    a, b = c.open(p, "r+"), c.open(p, "r+")
    a.write(b"AAAA")
    b.write(b"BBBB")
    a.close()  # publica v2
    with pytest.raises(DFShaError, match="409"):
        b.close()  # basada en v1 -> conflicto
    assert read_all(c, p)[:4] == b"AAAA"


def test_exception_inside_with_discards_changes(user):
    p = f"{user.home}/disc.bin"
    make_file(user, p, b"original")
    with pytest.raises(RuntimeError):
        with user.open(p, "r+") as f:
            f.write(b"CORRUPTO!")
            raise RuntimeError("falló la lógica del usuario")
    assert read_all(user, p) == b"original"


def test_other_users_cannot_open(make_user):
    alice, bob = make_user(), make_user()
    p = f"{alice.home}/priv.bin"
    make_file(alice, p, b"secreto")
    for mode in ("r", "r+", "w", "a"):
        with pytest.raises(DFShaError, match="403"):
            bob.open(p, mode)
    with pytest.raises(DFShaError, match="403"):
        bob.open(f"{alice.home}/nuevo.bin", "w")  # ni crear en el home de otro
    with pytest.raises(DFShaError, match="403"):
        bob.stat(p)
    # un handle ajeno tampoco se puede usar
    f = alice.open(p, "r")
    with pytest.raises(DFShaError, match="403"):
        bob._request("POST", "/fs/resolve", json={"handle": f.handle})
    f.close()


# locks

def test_exclusive_lock_blocks_other_sessions_and_writers(user, workdir):
    p = f"{user.home}/lk.bin"
    make_file(user, p, b"data")
    a = user.open(p, "r+", lock="exclusive")
    b = user.open(p, "r+")
    with pytest.raises(DFShaError, match="423"):
        b.lock("exclusive", timeout=0)
    with pytest.raises(DFShaError, match="423"):
        b.lock("shared", timeout=0)
    assert b.read() == b"data"  # los lectores no bloquean (snapshot)
    # escritores ajenos: commit, put y rm quedan bloqueados
    b.write(b"X")
    with pytest.raises(DFShaError, match="423"):
        b.flush()
    src = workdir / "s.bin"
    src.write_bytes(b"nuevo")
    with pytest.raises(DFShaError, match="423"):
        user.put(str(src), p)
    with pytest.raises(DFShaError, match="423"):
        user.rm(p)
    assert user.stat(p)["locks"] == ["exclusive"]
    a.write(b"OK")  # el dueño del lock sí puede publicar
    a.close()  # al cerrar suelta el lock
    b.close(discard=True)
    assert user.stat(p)["locks"] == []
    user.put(str(src), p)  # ahora sí
    assert read_all(user, p) == b"nuevo"


def test_shared_locks_coexist_but_block_writers(user):
    p = f"{user.home}/sh.bin"
    make_file(user, p, b"data")
    a, b = user.open(p, "r", lock="shared"), user.open(p, "r", lock="shared")
    w = user.open(p, "r+")
    with pytest.raises(DFShaError, match="423"):
        w.lock("exclusive", timeout=0)
    w.write(b"Z")
    with pytest.raises(DFShaError, match="423"):
        w.flush()
    a.close()
    with pytest.raises(DFShaError, match="423"):  # b sigue con su lock compartido
        w.flush()
    b.close()
    w.close()  # ya sin locks de otros: publica
    assert read_all(user, p) == b"Zata"


def test_lock_upgrade_downgrade_and_unlock(user):
    p = f"{user.home}/up.bin"
    make_file(user, p, b"x")
    a, b = user.open(p, "r+"), user.open(p, "r+")
    a.lock("shared")
    b.lock("shared")
    with pytest.raises(DFShaError, match="423"):
        a.lock("exclusive", timeout=0)  # b también tiene shared
    b.unlock()
    a.lock("exclusive", timeout=0)  # ahora sí puede subir
    with pytest.raises(DFShaError, match="423"):
        b.lock("shared", timeout=0)
    a.lock("shared")  # baja
    b.lock("shared")
    a.close(); b.close()


def test_blocking_lock_waits_until_released(user):
    p = f"{user.home}/wait.bin"
    make_file(user, p, b"x")
    a = user.open(p, "r+", lock="exclusive")
    b = user.open(p, "r+")
    threading.Timer(1.5, a.close).start()
    t0 = time.time()
    b.lock("exclusive", timeout=10)
    assert 1.0 < time.time() - t0 < 8
    b.close()


def test_exclusive_lock_gives_mutual_exclusion_for_read_modify_write(user):
    """n hilos suman a un contador guardado en el archivo: sin locks se perderían actualizaciones (o habría conflictos), con lock exclusivo el resultado es exacto"""
    p = f"{user.home}/counter.txt"
    make_file(user, p, b"0".ljust(8))
    N = 8

    def worker(_):
        with user.open(p, "r+", lock="exclusive", lock_timeout=60) as f:
            n = int(f.read().strip() or b"0")
            f.seek(0)
            f.write(str(n + 1).ljust(8).encode())

    with ThreadPoolExecutor(N) as pool:
        list(pool.map(worker, range(N)))
    assert int(read_all(user, p).strip()) == N


def test_concurrent_writers_to_disjoint_files_via_handles(user):
    def work(i):
        p = f"{user.home}/par{i}.bin"
        data = os.urandom(BS * 3 + i)
        make_file(user, p, data)
        return p, data
    with ThreadPoolExecutor(6) as pool:
        for p, data in pool.map(work, range(6)):
            assert read_all(user, p) == data


# lease y limpieza (lentas)

@pytest.mark.slow
def test_dead_client_releases_its_lock_after_lease_expires(user):
    p = f"{user.home}/dead.bin"
    make_file(user, p, b"data")
    victim = user.open(p, "r+", lock="exclusive")
    victim._stop_keepalive.set()  # el cliente "muere": deja de renovar su lease
    other = user.open(p, "r+")
    with pytest.raises(DFShaError, match="423"):
        other.lock("exclusive", timeout=0)
    ttl = 60  # HANDLE_TTL por defecto + intervalo del monitor
    other.lock("exclusive", timeout=ttl + 40, poll=2)
    assert user.stat(p)["locks"] == ["exclusive"]
    other.close()
    with pytest.raises(DFShaError, match="404"):
        victim.client._request("POST", "/fs/keepalive", json={"handle": victim.handle})


@pytest.mark.slow
def test_abandoned_session_blocks_are_garbage_collected(user):
    """bloques mandados a los datanodes por una sesión que nunca publicó (cliente muerto)"""
    p = f"{user.home}/ghost.bin"
    make_file(user, p, b"base")
    f = user.open(p, "r+", block_size=BS)
    f.write(os.urandom(2 * BS))
    f._stage()  # escribe bloques nuevos, pero nunca hace commit
    staged = {m["block_id"] for m in f._staged.values()}
    assert staged and staged <= set().union(*(node_blocks(n) for n in NODES))
    f._stop_keepalive.set()
    wait_until(lambda: not (staged & set().union(*(node_blocks(n) for n in NODES))), 200,
               "bloques sin publicar liberados tras expirar la sesión", interval=5)
    assert read_all(user, p) == b"base"


@pytest.mark.slow
def test_old_version_blocks_retained_for_open_reader_then_collected(user):
    p = f"{user.home}/ret.bin"
    make_file(user, p, os.urandom(2 * BS))
    old = block_ids(user, p)
    reader = user.open(p, "r")
    make_file(user, p, b"nueva version")
    all_blocks = lambda: set().union(*(node_blocks(n) for n in NODES))
    assert set(old) <= all_blocks()  # retenidos mientras el lector siga abierto
    assert len(reader.read()) == 2 * BS
    reader.close()
    wait_until(lambda: not (set(old) & all_blocks()), 200, "GC de la versión retenida", interval=5)
