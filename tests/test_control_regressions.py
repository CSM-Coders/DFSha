"""regresiones http de leases, snapshots, namespace e inventarios de réplicas"""
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control_node"))
import app as control
import storage
import dfsha_security as sec
from cluster import cluster


@pytest.fixture
def api(monkeypatch):
    storage.init_db()
    monkeypatch.setattr(cluster, "write", lambda op, **kw: storage.OPS[op](**kw))
    monkeypatch.setattr(cluster, "can_serve", lambda: True)
    monkeypatch.setattr(control, "_delete_blocks", lambda blocks: None)
    control.DATANODES.clear()
    control.HANDLE_SEEN.clear()
    control._inventory_challenges.clear()
    control._pending_replicas.clear()
    for node in ("n1", "n2"):
        control.DATANODES[node] = {"address": node + ":6000", "internal_address": node + ":6100",
                                   "used_bytes": 0, "last_seen": time.time()}
    return TestClient(control.app)


def user(api):
    name = "u" + uuid.uuid4().hex[:8]
    body = {"username": name, "password": "local-test-password"}
    assert api.post("/auth/register", json=body).status_code == 200
    token = api.post("/auth/login", json=body).json()["token"]
    return name, {"Authorization": "Bearer " + token}


def init(api, headers, path):
    response = api.post("/files/init", json={"path": path, "size": 3}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def complete(api, headers, plan):
    return api.post("/files/complete", headers=headers, json={"upload_id": plan["upload_id"], "blocks": [
        {"block_id": b["block_id"], "checksum": "a" * 64,
         "written": [n["node_id"] for n in b["replicas"]]} for b in plan["blocks"]]})


def test_upload_renewal_refreshes_lease_tokens_and_checks_owner(api, monkeypatch):
    name, headers = user(api)
    _, stranger = user(api)
    initial_time = time.time()
    monkeypatch.setattr(control.time, "time", lambda: initial_time)
    plan = init(api, headers, "/" + name + "/f")
    assert plan["lease_ttl"] == min(control.UPLOAD_TTL, control.BLOCK_TOKEN_TTL)
    assert api.post("/files/renew", headers=stranger, json={"upload_id": plan["upload_id"]}).status_code == 403
    monkeypatch.setattr(control.time, "time", lambda: initial_time + 590)
    for info in control.DATANODES.values():
        info["last_seen"] = initial_time + 590  # los nodos siguen mandando heartbeat durante la transferencia
    response = api.post("/files/renew", headers=headers, json={"upload_id": plan["upload_id"]})
    assert response.status_code == 200
    renewed = response.json()
    assert [b["block_id"] for b in renewed["blocks"]] == [b["block_id"] for b in plan["blocks"]]
    assert renewed["blocks"][0]["token"] != plan["blocks"][0]["token"]
    monkeypatch.setattr(control.time, "time", lambda: initial_time + 610)
    assert plan["upload_id"] not in storage.stale_uploads(initial_time + 610 - control.UPLOAD_TTL)
    b = renewed["blocks"][0]
    assert sec.verify_block_token(control.KEYS, b["token"], b["block_id"], "w")
    assert complete(api, headers, renewed).status_code == 200


def test_revocation_prevents_upload_renewal(api):
    alice, ha = user(api)
    bob, hb = user(api)
    path = "/" + alice + "/shared"
    assert api.post("/mkdir", headers=ha, json={"path": path}).status_code == 200
    grant = {"path": path, "principal": "user:" + bob, "perm": "rw"}
    assert api.post("/acl/set", headers=ha, json=grant).status_code == 200
    plan = init(api, hb, path + "/file")
    assert api.post("/acl/set", headers=ha, json={**grant, "perm": "none"}).status_code == 200
    assert api.post("/files/renew", headers=hb, json={"upload_id": plan["upload_id"]}).status_code == 403


def test_upload_cannot_commit_over_a_directory_created_after_init(api):
    name, headers = user(api)
    path = "/" + name + "/collision"
    plan = init(api, headers, path)
    assert api.post("/mkdir", headers=headers, json={"path": path}).status_code == 200
    assert complete(api, headers, plan).status_code == 409
    assert storage.get_file(path) is None and storage.get_dir_owner(path) == name


def test_deleted_handle_keeps_old_snapshot_but_cannot_change_recreated_file(api):
    name, headers = user(api)
    path = "/" + name + "/f"
    old = init(api, headers, path)
    assert complete(api, headers, old).status_code == 200
    opened = api.post("/fs/open", headers=headers, json={"path": path, "mode": "r+"}).json()
    handle = opened["handle"]
    assert api.post("/rm", headers=headers, json={"path": path}).status_code == 200
    new = init(api, headers, path)
    assert complete(api, headers, new).status_code == 200
    assert api.post("/fs/commit", headers=headers, json={"handle": handle, "size": 0, "blocks": []}).status_code == 404
    assert storage.get_file(path)["size"] == 3
    snapshot = api.post("/fs/resolve", headers=headers, json={"handle": handle})
    assert snapshot.status_code == 200
    assert snapshot.json()["blocks"][0]["block_id"] == old["blocks"][0]["block_id"]
    assert api.post("/fs/refresh", headers=headers, json={"handle": handle}).status_code == 404
    assert api.post("/fs/close", headers=headers, json={"handle": handle}).status_code == 200


def seed_file(path="/owner/f", bid="a" * 32):
    if not storage.user_exists("owner"):
        storage.register_user("owner", "test-hash")
    blocks = [{"block_id": bid, "index": 0, "size": 3, "nodes": ["n1", "n2"], "checksum": "a" * 64}]
    upload = uuid.uuid4().hex
    storage.create_upload(upload, path, "owner", 3, 65536, blocks, time.time())
    storage.commit_upload(upload, blocks, time.time())


def beat(api, **extra):
    response = api.post("/datanodes/register", headers={"X-DFSha-Node-Token": sec.make_node_token(control.KEYS, "n1")},
                        json={"node_id": "n1", "address": "n1:6000", "internal_address": "n1:6100",
                              "inventory_id": "boot-one", **extra})
    assert response.status_code == 200, response.text
    return response.json()


def test_empty_inventory_removes_missing_replica_and_monitor_rebuilds_it(api, monkeypatch):
    seed_file()
    first = beat(api, inventory_blocks=[], inventory_generation=1)
    assert storage.get_file("/owner/f")["blocks"][0]["nodes"] == ["n1", "n2"]  # todavía no hay desafío
    second = beat(api, inventory_blocks=[], inventory_generation=2, inventory_request=first["inventory_request"])
    assert storage.get_file("/owner/f")["blocks"][0]["nodes"] == ["n2"]
    copies = []
    monkeypatch.setattr(control, "_rpc", lambda node, addr, method, request, **kw:
                        copies.append((node, method)) or SimpleNamespace(success=True))
    control._reconcile_once()
    assert ("n1", "ReplicateBlock") in copies
    assert set(storage.get_file("/owner/f")["blocks"][0]["nodes"]) == {"n1", "n2"}
    # una respuesta atrasada del desafío anterior no descarta la copia reparada
    beat(api, inventory_blocks=[], inventory_generation=2, inventory_request=first["inventory_request"])
    assert "n1" in storage.get_file("/owner/f")["blocks"][0]["nodes"]
    assert second["inventory_request"] != first["inventory_request"]


def test_inventory_never_discards_blocks_committed_after_challenge(api):
    seed_file()
    first = beat(api)
    seed_file("/owner/recent", "b" * 32)
    beat(api, inventory_blocks=["a" * 32], inventory_generation=1, inventory_request=first["inventory_request"])
    assert "n1" in storage.get_file("/owner/recent")["blocks"][0]["nodes"]


def test_inventory_ignores_wrong_nonce_old_generation_and_reboot(api):
    seed_file()
    first = beat(api, inventory_generation=5)
    beat(api, inventory_blocks=[], inventory_generation=6, inventory_request="unknown")
    beat(api, inventory_blocks=[], inventory_generation=5, inventory_request=first["inventory_request"])
    replacement = beat(api, inventory_id="boot-two", inventory_blocks=[], inventory_generation=6,
                       inventory_request=first["inventory_request"])
    assert "n1" in storage.get_file("/owner/f")["blocks"][0]["nodes"]
    assert replacement["inventory_request"] != first["inventory_request"]


def test_inventory_taken_before_repair_does_not_remove_the_new_copy(api, monkeypatch):
    seed_file()
    challenge = beat(api)
    block = storage.get_file("/owner/f")["blocks"][0]
    storage.drop_replica(block["block_id"], "n1")
    monkeypatch.setattr(control, "_rpc", lambda *args, **kw: SimpleNamespace(success=True))
    assert control._copy_block("/owner/f", block, "n2", "n1", control._alive_nodes())
    # el nodo había escaneado el disco antes de terminar la copia y su respuesta llega después
    beat(api, inventory_blocks=[], inventory_generation=1, inventory_request=challenge["inventory_request"])
    assert "n1" in storage.get_file("/owner/f")["blocks"][0]["nodes"]


def test_successful_keepalive_survives_an_older_expiry_check(api):
    name, headers = user(api)
    path = "/" + name + "/f"
    handle = api.post("/fs/open", headers=headers, json={"path": path, "mode": "w"}).json()["handle"]
    control.HANDLE_SEEN[handle] = time.time() - control.HANDLE_TTL - 10
    old_cutoff = time.time() - control.HANDLE_TTL
    assert api.post("/fs/keepalive", headers=headers, json={"handle": handle}).status_code == 200
    assert control._close_handle(handle, stale_before=old_cutoff) is None
    assert storage.get_handle(handle) is not None
