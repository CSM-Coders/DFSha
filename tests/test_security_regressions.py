"""regresiones de seguridad e inventario que corren sin servicios ni contenedores"""
import hashlib
import importlib.util
import os
from pathlib import Path
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def dn(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SCRUB_MB_PER_SEC", "0")
    monkeypatch.syspath_prepend(str(ROOT / "data_node"))
    spec = importlib.util.spec_from_file_location("dn_regression_" + uuid.uuid4().hex,
                                                 ROOT / "data_node" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Context:
    def __init__(self, token):
        self.token = token

    def invocation_metadata(self):
        return [("x-dfsha-token", self.token)]

    def abort(self, code, message):
        raise AssertionError(f"{code}: {message}")


def write(dn, bid, data, context=None):
    context = context or Context(dn.sec.make_block_token(dn.KEYS, bid, "w"))
    return dn._do_write(dn.dfsha_pb2.Block(block_id=bid, data=data,
                        checksum=hashlib.sha256(data).hexdigest()), context)


def test_same_write_token_is_idempotent_but_cannot_change_published_content(dn, tmp_path):
    bid, original = uuid.uuid4().hex, b"publicado una sola vez"
    context = Context(dn.sec.make_block_token(dn.KEYS, bid, "w"))
    assert write(dn, bid, original, context).success
    raw = (tmp_path / (bid + ".blk")).read_bytes()
    assert write(dn, bid, original, context).success
    assert (tmp_path / (bid + ".blk")).read_bytes() == raw
    rejected = write(dn, bid, b"alterado con el mismo token", context)
    assert not rejected.success and "inmutable" in rejected.message
    assert dn._load_block(bid)[0] == original


def test_concurrent_first_writes_choose_one_immutable_value(dn, tmp_path):
    bid = uuid.uuid4().hex
    payloads = [b"contenido A", b"contenido B"] * 8
    barrier = threading.Barrier(len(payloads))

    def upload(data):
        barrier.wait(timeout=5)
        return data, write(dn, bid, data)

    with ThreadPoolExecutor(max_workers=len(payloads)) as pool:
        results = list(pool.map(upload, payloads))
    stored, checksum = dn._load_block(bid)
    assert stored in payloads and checksum == hashlib.sha256(stored).hexdigest()
    assert all(result.success == (data == stored) for data, result in results)
    assert list(tmp_path.glob("*.tmp")) == []


@pytest.mark.parametrize("corruption", ["altered_ciphertext", "wrong_valid_content"])
def test_internal_replication_repairs_corruption_and_checks_expected_checksum(dn, tmp_path, monkeypatch, corruption):
    bid, expected = uuid.uuid4().hex, b"contenido original correcto"
    assert write(dn, bid, expected if corruption == "altered_ciphertext" else b"contenido incorrecto").success
    if corruption == "altered_ciphertext":
        raw = bytearray((tmp_path / (bid + ".blk")).read_bytes())
        raw[-1] ^= 1
        (tmp_path / (bid + ".blk")).write_bytes(raw)
    assert not write(dn, bid, expected + b"x").success
    checksum = hashlib.sha256(expected).hexdigest()
    monkeypatch.setattr(dn, "_peer_channel", lambda address: nullcontext(object()))
    source = SimpleNamespace(ReadBlock=lambda *a, **kw: dn.dfsha_pb2.Block(
        block_id=bid, data=expected, checksum=checksum))
    monkeypatch.setattr(dn.dfsha_pb2_grpc, "DataNodeStub", lambda channel: source)
    request = dn.dfsha_pb2.ReplicateRequest(block_id=bid, source_address="source:6100",
                                           source_token="unused-in-this-unit-test", checksum="0" * 64)
    context = Context(dn.sec.make_block_token(dn.KEYS, bid, "x"))
    assert not dn._do_replicate(request, context).success
    request.checksum = checksum
    assert dn._do_replicate(request, context).success
    assert dn._load_block(bid) == (expected, checksum)
    assert dn._do_replicate(request, context).success  # reparación o reintento idempotente


def test_inventory_is_complete_and_separate_from_aged_gc_candidates(dn, tmp_path, monkeypatch):
    monkeypatch.setattr(dn, "CONTROL_NODE_URLS", ["control-a", "control-b"])
    old, recent = uuid.uuid4().hex, uuid.uuid4().hex
    assert write(dn, old, b"viejo").success
    before = time.time() - dn.ORPHAN_MIN_AGE - 5
    os.utime(tmp_path / (old + ".blk"), (before, before))
    regular, generation = dn._heartbeat_payloads({}, 0, True)
    assert generation == 0 and "inventory_blocks" not in regular["control-a"]
    # el desafío se recibió antes de una escritura que el snapshot tiene que incluir
    pending = {"control-a": "nonce-a"}
    assert write(dn, recent, b"reciente").success
    payloads, generation = dn._heartbeat_payloads(pending, generation, True)
    report = payloads["control-a"]
    assert generation == 1 and report["inventory_generation"] == generation
    assert report["inventory_id"] == dn.INVENTORY_ID
    assert report["inventory_request"] == "nonce-a"
    assert set(report["inventory_blocks"]) == {old, recent}
    assert report["block_ids"] == [old]
    assert "inventory_request" not in payloads["control-b"]
    assert "inventory_blocks" not in payloads["control-b"]


def test_heartbeat_answers_challenge_on_next_fresh_snapshot(dn, monkeypatch):
    monkeypatch.setattr(dn, "CONTROL_NODE_URLS", ["control"])
    bid, requests, sleeps = uuid.uuid4().hex, [], []

    def beat(url, payload):
        requests.append(payload)
        if len(requests) == 1:
            assert "inventory_blocks" not in payload
            assert write(dn, bid, b"despues-del-desafio").success
            return {"leader": True, "inventory_request": "next-snapshot"}
        assert payload["inventory_request"] == "next-snapshot"
        assert bid in payload["inventory_blocks"]
        return {"leader": True}

    class Finished(BaseException):
        pass

    def pause(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise Finished()

    monkeypatch.setattr(dn, "_beat", beat)
    monkeypatch.setattr(dn.time, "sleep", pause)
    with pytest.raises(Finished):
        dn.heartbeat_loop()
    assert len(requests) == 2


def test_active_2fa_setup_returns_conflict_and_preserves_enabled_secret(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "control_node"))
    import access
    import auth_routes
    import storage

    storage.init_db()
    monkeypatch.setattr(auth_routes.cluster, "write", lambda op, **kw: storage.OPS[op](**kw))
    monkeypatch.setattr(access, "_totp_used", {})
    username, password = "regression_user", "password-for-local-test"
    storage.register_user(username, access.hash_password(password))
    app = FastAPI()
    app.include_router(auth_routes.router)
    api = TestClient(app)
    headers = {"Authorization": "Bearer " + access.make_token(username)}
    setup = api.post("/auth/2fa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    enabled = api.post("/auth/2fa/enable", json={"code": access.totp_code(secret)}, headers=headers)
    assert enabled.status_code == 200
    response = api.post("/auth/2fa/setup", headers=headers)
    assert response.status_code == 409
    current = storage.get_user(username)
    assert current["totp_enabled"] and current["totp_secret"] == secret
    # el camino autorizado pide contraseña + otro código y deja volver a inscribir
    disabled = api.post("/auth/2fa/disable", headers=headers, json={
        "password": password, "code": access.totp_code(secret, at=time.time() + 30)})
    assert disabled.status_code == 200
    assert api.post("/auth/2fa/setup", headers=headers).status_code == 200
