"""alta disponibilidad del control node: raft (3 nodos), failover, quórum y recuperación"""
import os
import subprocess

import pytest

import dfsha_client
from conftest import CONTROLS, CONTROL_PORTS, ROOT, compose, find_leader, raft_status, wait_until
from dfsha_client import DFShaClient, DFShaError

pytestmark = pytest.mark.usefixtures("cluster_up")

KB = 1024


def read_all(client, path) -> bytes:
    with client.open(path, "r") as f:
        return f.read()


def solo(name: str, token: str = None) -> DFShaClient:
    """cliente que habla solo con un control node concreto (sin failover)"""
    return DFShaClient(f"https://localhost:{CONTROL_PORTS[name]}", token)


def all_statuses():
    return {n: raft_status(n) for n in CONTROLS}


def converged(nodes=CONTROLS):
    """los nodos indicados responden, hay exactamente un líder y todos aplicaron todo lo comprometido"""
    st = {n: raft_status(n) for n in nodes}
    if not all(st.values()):
        return False
    leaders = [s for s in st.values() if s["is_leader"]]
    if len(leaders) != 1 or not leaders[0]["can_serve"]:
        return False
    return all(s["last_applied"] == leaders[0]["commit_idx"] and s["leader"] == leaders[0]["self"] for s in st.values())


@pytest.fixture
def stop_control():
    stopped = []

    def _stop(name):
        compose("stop", name)
        stopped.append(name)

    yield _stop
    for n in stopped:
        compose("start", n)
    wait_until(lambda: find_leader() and converged(), 120, "cluster Raft recuperado y sincronizado", interval=2)


# estado normal

def test_exactly_one_leader_and_all_nodes_in_sync():
    wait_until(converged, 60, "convergencia Raft")
    st = all_statuses()
    assert sum(s["is_leader"] for s in st.values()) == 1
    assert len({s["leader"] for s in st.values()}) == 1
    assert all(s["partners"] == 2 for s in st.values())


def test_every_node_accepts_requests_and_sessions_work_across_nodes(make_user, tmp_path):
    user = make_user()
    for name in CONTROLS:
        c = solo(name, user.token)  # el mismo token vale en cualquier control node
        d = f"{user.home}/via_{name}"
        c.mkdir(d)  # un seguidor reenvía al líder (proxy)
        src = tmp_path / f"{name}.bin"
        src.write_bytes(os.urandom(100 * KB))
        c.put(str(src), f"{d}/f.bin", block_size=64 * KB)
        dst = tmp_path / f"{name}.out"
        c.get(f"{d}/f.bin", str(dst))
        assert dst.read_bytes() == src.read_bytes()
    # y todos ven lo mismo, con el nodo que sea
    for name in CONTROLS:
        assert solo(name, user.token).ls(user.home)["dirs"] == sorted(f"{user.home}/via_{c}" for c in CONTROLS)


def test_writes_are_replicated_to_every_node(make_user):
    user = make_user()
    user.mkdir(f"{user.home}/repl")
    wait_until(converged, 30, "los seguidores aplicaron la escritura")
    commits = {n: s["commit_idx"] for n, s in all_statuses().items()}
    assert len(set(commits.values())) == 1, commits


# fallos (lentos)

@pytest.mark.slow
def test_leader_failover_service_and_open_sessions_survive(user, stop_control, tmp_path):
    path = f"{user.home}/ha.bin"
    with user.open(path, "w", block_size=64 * KB) as f:
        f.write(b"base" * 1000)
    other = user.open(path, "r+")
    f = user.open(path, "r+", lock="exclusive")  # sesión con lock y cambios sin publicar
    f.seek(0)
    f.write(b"NUEVO")
    old, _ = find_leader()

    stop_control(old)  # cae el líder
    new = wait_until(lambda: (find_leader() or (old,))[0] != old and find_leader(), 60, "nuevo líder")
    assert new[0] != old

    # 1) el servicio sigue: lecturas, escrituras de metadatos, put/get
    assert read_all(user, path)[:4] == b"base"
    user.mkdir(f"{user.home}/tras_failover")
    src = tmp_path / "s.bin"
    src.write_bytes(os.urandom(200 * KB))
    user.put(str(src), f"{user.home}/tras_failover/x.bin", block_size=64 * KB)
    dst = tmp_path / "d.bin"
    user.get(f"{user.home}/tras_failover/x.bin", str(dst))
    assert dst.read_bytes() == src.read_bytes()

    # 2) la sesión abierta y su lock (estado replicado) sobreviven: los demás siguen bloqueados...
    with pytest.raises(DFShaError, match="423"):
        other.lock("exclusive", timeout=0)
    # ... y la sesión original puede publicar contra el líder nuevo
    f.close()
    assert read_all(user, path)[:9] == b"NUEVOaseb"
    other.close(discard=True)
    assert user.stat(path)["locks"] == []

    # 3) el nodo caído vuelve y se pone al día (lo hace el fixture), aquí probamos otra caída seguida
    compose("start", old)
    wait_until(lambda: converged(), 120, "el antiguo líder se sincroniza como seguidor", interval=2)
    st = raft_status(old)
    assert not st["is_leader"] and st["last_applied"] > 0
    second, _ = find_leader()
    stop_control(second)
    wait_until(lambda: (find_leader() or (second,))[0] != second and find_leader(), 60, "segunda elección")
    assert read_all(user, path)[:9] == b"NUEVOaseb"


@pytest.mark.slow
def test_follower_failure_is_invisible(user, stop_control):
    leader, _ = find_leader()
    follower = next(n for n in CONTROLS if n != leader)
    stop_control(follower)
    for i in range(5):
        user.mkdir(f"{user.home}/sin_seguidor{i}")  # mayoría (2 de 3) intacta
    assert len(user.ls(user.home)["dirs"]) == 5
    assert find_leader()[0] == leader  # no hubo cambio de líder


@pytest.mark.slow
def test_quorum_loss_blocks_writes_and_recovery_keeps_data(user, stop_control, monkeypatch):
    user.mkdir(f"{user.home}/antes")
    leader, _ = find_leader()
    others = [n for n in CONTROLS if n != leader]
    stop_control(others[0])
    stop_control(others[1])  # queda 1 de 3: sin mayoría
    monkeypatch.setattr(dfsha_client, "RETRY_SECONDS", 5)
    wait_until(lambda: not (raft_status(leader) or {}).get("can_serve"), 30, "el nodo solitario deja de ser líder")
    with pytest.raises(DFShaError, match="503"):
        user.mkdir(f"{user.home}/sin_quorum")  # no se puede confirmar nada (nunca se acepta sin mayoría)
    with pytest.raises(DFShaError, match="503"):
        user.ls(user.home)  # ni siquiera leer: así no se sirven datos que podrían estar atrasados

    compose("start", others[0])  # vuelve la mayoría
    wait_until(find_leader, 60, "líder tras recuperar quórum")
    monkeypatch.setattr(dfsha_client, "RETRY_SECONDS", 25)
    assert user.ls(user.home)["dirs"] == [f"{user.home}/antes"]  # no se perdió nada ni apareció la escritura rechazada
    user.mkdir(f"{user.home}/despues")


@pytest.mark.slow
def test_full_cluster_restart_recovers_metadata_from_journal(user, tmp_path):
    path = f"{user.home}/persist.bin"
    data = os.urandom(300 * KB)
    src = tmp_path / "p.bin"
    src.write_bytes(data)
    user.put(str(src), path, block_size=64 * KB)
    with user.open(f"{user.home}/handle.txt", "w") as f:
        f.write(b"x")
    held = user.open(path, "r+", lock="shared")  # un handle y un lock vivos durante el reinicio
    compose("restart", *CONTROLS)
    wait_until(lambda: find_leader() and converged(), 120, "cluster recuperado desde el journal", interval=2)
    assert user.ls(user.home)["files"]  # el token firmado sigue valiendo: no hay que volver a loguearse
    assert read_all(user, path) == data  # metadatos intactos
    assert user.stat(path)["locks"] == ["shared"]  # y el lock replicado también
    held.close()
    assert user.stat(path)["locks"] == []


@pytest.mark.slow
def test_node_with_wiped_disk_resyncs_from_leader(user, stop_control):
    user.mkdir(f"{user.home}/d1")
    leader, _ = find_leader()
    victim = next(n for n in CONTROLS if n != leader)
    compose("stop", victim)
    compose("rm", "-f", victim)
    project = os.environ.get("COMPOSE_PROJECT_NAME", ROOT.name.lower())
    subprocess.run(["docker", "volume", "rm", f"{project}_{victim}_data"], capture_output=True, check=True)
    user.mkdir(f"{user.home}/d2")  # el cluster sigue escribiendo sin ese nodo
    compose("up", "-d", victim)
    wait_until(converged, 120, "el nodo sin disco se sincronizó con el líder", interval=2)
    st = raft_status(victim)
    assert st["last_applied"] == raft_status(leader)["commit_idx"] and not st["is_leader"]
    # prueba final: sin los otros dos nodos este ya tiene todo el estado
    others = [n for n in CONTROLS if n != victim]
    for n in others:
        stop_control(n)
    compose("start", others[0])
    wait_until(lambda: find_leader(), 90, "elección con el nodo resincronizado", interval=2)
    assert user.ls(user.home)["dirs"] == [f"{user.home}/d1", f"{user.home}/d2"]


@pytest.mark.slow
def test_control_nodes_swapping_ips_after_restart_still_agree_on_the_leader(user):
    """docker reasigna ips al reiniciar contenedores, los nodos raft se tienen que reconocer por nombre y no por una ip vieja"""
    for round_ in range(2):
        compose("stop", *CONTROLS)
        for n in reversed(CONTROLS) if round_ == 0 else CONTROLS[1:] + CONTROLS[:1]:
            compose("start", n)  # orden distinto en cada ronda => ips distintas
        wait_until(lambda: find_leader() and converged(), 120,
                   f"consenso tras reinicio en otro orden (ronda {round_})", interval=2)
        user.mkdir(f"{user.home}/ronda{round_}")
        for name in CONTROLS:  # todos los nodos reconocen al mismo líder y todos reenvían bien
            assert solo(name, user.token).ls(user.home)["dirs"][-1] == f"{user.home}/ronda{round_}"
