"""api del control node probada en proceso (sin cluster ni docker): `cluster.write` se conecta directo con la máquina de estados y así se prueba rápido toda la lógica de permisos y políticas"""
import sys
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control_node"))

import access  # noqa: E402
import app as app_module  # noqa: E402
import config  # noqa: E402
import storage  # noqa: E402
from cluster import cluster  # noqa: E402


@pytest.fixture
def api(monkeypatch):
    storage.init_db()
    monkeypatch.setattr(cluster, "write", lambda op, **kw: storage.OPS[op](**kw))
    app_module.DATANODES.clear()
    for n in ("n1", "n2"):
        app_module.DATANODES[n] = {"address": f"{n}:6000", "internal_address": f"{n}:6100",
                                   "used_bytes": 0, "last_seen": time.time()}
    return TestClient(app_module.app)


def make_user(api, name=None):
    name = name or "u" + uuid.uuid4().hex[:8]
    assert api.post("/auth/register", json={"username": name, "password": "secret123"}).status_code == 200
    tok = api.post("/auth/login", json={"username": name, "password": "secret123"}).json()["token"]
    return name, {"Authorization": f"Bearer {tok}"}


def test_reserved_names_cannot_be_registered(api):
    r = api.post("/auth/register", json={"username": "admin", "password": "secret123"})
    assert r.status_code == 409 and "reservado" in r.json()["detail"]
    assert api.post("/auth/register", json={"username": "ADMIN", "password": "secret123"}).status_code == 409


def test_closed_registration_only_lets_admin_create_accounts(api, monkeypatch):
    storage.register_user("admin", access.hash_password("admin-pass"))
    admin = {"Authorization": f"Bearer {access.make_token('admin')}"}
    monkeypatch.setattr(config, "ALLOW_REGISTRATION", False)
    body = {"username": "nuevo_usuario", "password": "secret123"}
    assert api.post("/auth/register", json=body).status_code == 401  # sin sesión: hay que autenticarse
    _, ana = make_user_closed(api, monkeypatch)
    assert api.post("/auth/register", json=body, headers=ana).status_code == 403  # un usuario normal tampoco
    assert api.post("/auth/register", json=body, headers=admin).status_code == 200  # el admin sí


def make_user_closed(api, monkeypatch):
    """crea un usuario saltándose la política (para probar que un no-admin no puede registrar a otros)"""
    monkeypatch.setattr(config, "ALLOW_REGISTRATION", True)
    out = make_user(api)
    monkeypatch.setattr(config, "ALLOW_REGISTRATION", False)
    return out


def test_size_and_path_limits(api):
    name, h = make_user(api)
    huge = api.post("/files/init", json={"path": f"/{name}/x", "size": 10 ** 15}, headers=h)
    assert huge.status_code == 400 and "bloques" in huge.json()["detail"]
    assert api.post("/files/init", json={"path": f"/{name}/ok", "size": 100}, headers=h).status_code == 200
    assert api.post("/mkdir", json={"path": f"/{name}/" + "a" * 300}, headers=h).status_code == 400  # nombre demasiado largo
    assert api.post("/mkdir", json={"path": "/" + "/".join(["d"] * 3000)}, headers=h).status_code == 400
    assert api.post("/mkdir", json={"path": "relativo"}, headers=h).status_code == 400


def test_topology_listing_needs_a_session(api):
    assert api.get("/datanodes").status_code == 401
    _, h = make_user(api)
    assert set(api.get("/datanodes", headers=h).json()) == {"n1", "n2"}


def test_permissions_are_rechecked_when_an_upload_is_completed(api):
    alice, ha = make_user(api)
    bob, hb = make_user(api)
    assert api.post("/mkdir", json={"path": f"/{alice}/equipo"}, headers=ha).status_code == 200
    assert api.post("/acl/set", json={"path": f"/{alice}/equipo", "principal": f"user:{bob}", "perm": "rw"},
                    headers=ha).status_code == 200
    plan = api.post("/files/init", json={"path": f"/{alice}/equipo/b.bin", "size": 100}, headers=hb)
    assert plan.status_code == 200
    plan = plan.json()
    blocks = [{"block_id": b["block_id"], "checksum": "0" * 64, "written": [r["node_id"] for r in b["replicas"]]}
              for b in plan["blocks"]]
    # alice revoca el permiso mientras bob todavía está subiendo
    api.post("/acl/set", json={"path": f"/{alice}/equipo", "principal": f"user:{bob}", "perm": "none"}, headers=ha)
    done = api.post("/files/complete", json={"upload_id": plan["upload_id"], "blocks": blocks}, headers=hb)
    assert done.status_code == 403
    assert storage.get_file(f"/{alice}/equipo/b.bin") is None  # no se publicó nada
    # y si el permiso sigue vigente, el mismo flujo termina bien
    api.post("/acl/set", json={"path": f"/{alice}/equipo", "principal": f"user:{bob}", "perm": "rw"}, headers=ha)
    plan = api.post("/files/init", json={"path": f"/{alice}/equipo/c.bin", "size": 100}, headers=hb).json()
    blocks = [{"block_id": b["block_id"], "checksum": "0" * 64, "written": [r["node_id"] for r in b["replicas"]]}
              for b in plan["blocks"]]
    assert api.post("/files/complete", json={"upload_id": plan["upload_id"], "blocks": blocks}, headers=hb).status_code == 200
    assert storage.get_file(f"/{alice}/equipo/c.bin")["owner"] == bob


def test_acl_inheritance_and_levels_in_process(api):
    alice, ha = make_user(api)
    bob, hb = make_user(api)
    for p in ("a", "a/b", "a/b/c"):
        api.post("/mkdir", json={"path": f"/{alice}/{p}"}, headers=ha)
    assert api.get("/ls", params={"path": f"/{alice}/a/b/c"}, headers=hb).status_code == 403
    api.post("/acl/set", json={"path": f"/{alice}/a", "principal": f"user:{bob}", "perm": "r"}, headers=ha)
    assert api.get("/ls", params={"path": f"/{alice}/a/b/c"}, headers=hb).status_code == 200  # heredado hacia abajo
    assert api.post("/mkdir", json={"path": f"/{alice}/a/b/c/x"}, headers=hb).status_code == 403  # r no crea
    api.post("/acl/set", json={"path": f"/{alice}/a/b", "principal": f"user:{bob}", "perm": "rw"}, headers=ha)
    assert api.post("/mkdir", json={"path": f"/{alice}/a/b/c/x"}, headers=hb).status_code == 200  # rw en un ancestro
    assert api.post("/mkdir", json={"path": f"/{alice}/a/y"}, headers=hb).status_code == 403  # pero no por encima
    assert storage.get_dir_owner(f"/{alice}/a/b/c/x") == bob
    assert api.post("/rmdir", json={"path": f"/{alice}/a/b/c/x"}, headers=ha).status_code == 200  # el dueño del árbol manda
