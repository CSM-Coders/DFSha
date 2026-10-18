"""pruebas de integración contra un cluster ya levantado (docker compose up --build -d, pip install -r tests/requirements.txt, pytest tests -v para todo o pytest tests -v -m "not slow" sin las lentas), usan DFShaClient directo y `docker compose` para revisar o romper nodos"""
import os
import sys
import time
import uuid
import hashlib
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "common"))

CA = str(ROOT / "certs" / "ca.crt")
os.environ.setdefault("DFSHA_CA_CERT", CA)

import dfsha_security as sec  # noqa: E402
from dfsha_client import DFShaClient  # noqa: E402

URL = os.environ.get("CONTROL_NODE_URL", "https://localhost:8001,https://localhost:8002,https://localhost:8003")


def _cluster_secret() -> str:
    """el mismo secreto con el que se levantó docker compose (.env o el valor de desarrollo por defecto)"""
    if os.environ.get("CLUSTER_SECRET"):
        return os.environ["CLUSTER_SECRET"]
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("CLUSTER_SECRET=") and line.split("=", 1)[1].strip():
                return line.split("=", 1)[1].strip()
    return "dfsha-dev-secret-change-me"


KEYS = sec.Keys(_cluster_secret())


def block_token(block_id: str, op: str, ttl: float = 600) -> str:
    """token de acceso a bloque como el que daría el control node (las pruebas conocen el secreto)"""
    return sec.make_block_token(KEYS, block_id, op, ttl)


def datanode_channel(port: int, ca: bool = True):
    """canal grpc al puerto público de un datanode (tls verificando la ca del cluster)"""
    import grpc
    if not ca:
        return grpc.insecure_channel(f"localhost:{port}")
    return grpc.secure_channel(f"localhost:{port}", grpc.ssl_channel_credentials(root_certificates=Path(CA).read_bytes()))
NODES = ["datanode1", "datanode2", "datanode3"]
CONTROLS = ["control1", "control2", "control3"]
CONTROL_PORTS = {"control1": 8001, "control2": 8002, "control3": 8003}


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: pruebas de tolerancia a fallos (esperan al monitor, al lease o mueven mucho dato)")
    config.addinivalue_line("markers", "integration: necesitan el cluster levantado (docker compose up)")


def pytest_collection_modifyitems(items):
    """marca como `integration` toda prueba que use el cluster (fixtures cluster_up/user/make_user)"""
    for item in items:
        if {"cluster_up", "user", "make_user"} & set(getattr(item, "fixturenames", ())):
            item.add_marker(pytest.mark.integration)


def compose(*args: str, check: bool = True) -> str:
    r = subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)}: {r.stderr}")
    return r.stdout


def node_blocks(node: str) -> set[str]:
    out = compose("exec", "-T", node, "sh", "-c", "ls /data 2>/dev/null | grep '\\.blk$' || true")
    return {line[:-4] for line in out.split() if line.endswith(".blk")}


def wait_until(cond, timeout: float, what: str, interval: float = 2.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = cond()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timeout esperando: {what}")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def raft_status(name: str):
    """estado raft de un control node (None si no responde)"""
    import requests
    try:
        return requests.get(f"https://localhost:{CONTROL_PORTS[name]}/raft/status", timeout=2, verify=CA).json()
    except Exception:
        return None


def find_leader():
    """(nombre, estado) del control node que ya sirve como líder, o None"""
    for name in CONTROLS:
        st = raft_status(name)
        if st and st.get("can_serve"):
            return name, st
    return None


@pytest.fixture(scope="session")
def cluster_up():
    c = DFShaClient(URL)
    wait_until(find_leader, 90, "un ControlNode líder sirviendo")
    wait_until(lambda: c._request("GET", "/health")["datanodes_alivos"] >= 3, 60, "3 DataNodes vivos")


@pytest.fixture
def make_user():
    def _make() -> DFShaClient:
        name = "u" + uuid.uuid4().hex[:10]
        c = DFShaClient(URL)
        c.register(name, "secret123")
        c.login(name, "secret123")
        c.home = "/" + name
        return c
    return _make


@pytest.fixture
def user(make_user):
    return make_user()


@pytest.fixture
def workdir(tmp_path):
    return tmp_path
