"""regresiones de transferencias: lease renovable, snapshot y publicación atómica"""
import hashlib
import threading

import pytest

from dfsha_client import DFShaClient, DFShaError, DFShaFile, PARALLEL_BLOCKS


def _plan(token="expired", ttl=0.06):
    return {"upload_id": "upload", "block_size": 4, "lease_ttl": ttl,
            "blocks": [{"block_id": "block", "index": 0, "size": 4, "token": token,
                        "replicas": [{"node_id": "n1", "address": "n1:6000"}]}]}


def test_put_renews_active_upload_and_retries_expired_block_token(monkeypatch, tmp_path):
    """una escritura lenta se pasa de su permiso inicial sin perder el upload ni publicar antes de tiempo"""
    client = DFShaClient("https://unused")
    src = tmp_path / "input"
    src.write_bytes(b"data")
    renewed = threading.Event()
    requests, writes, progress = [], [], []
    result = {"ok": True, "under_replicated_blocks": 0}

    def request(method, path, **kwargs):
        requests.append(path)
        if path == "/files/init":
            return _plan()
        if path == "/files/renew":
            renewed.set()
            return _plan("fresh")
        if path == "/files/complete":
            assert renewed.is_set()
            assert kwargs["json"]["blocks"][0]["written"] == ["n1"]
            return result
        pytest.fail(f"petición inesperada: {path}")

    def write(block, data, ca):
        writes.append((block["token"], data))
        assert renewed.wait(2), "el upload no se renovó durante la escritura bloqueada"
        return {"block_id": block["block_id"], "checksum": hashlib.sha256(data).hexdigest(),
                "written": ["n1"] if block["token"] == "fresh" else []}

    monkeypatch.setattr(client, "_request", request)
    monkeypatch.setattr(client, "_write_block", write)
    assert client.put(str(src), "/u/file", progress=lambda *args: progress.append(args)) == result
    assert writes == [("expired", b"data"), ("fresh", b"data")]
    assert progress == [(0, 1, 1, 1)]
    assert requests[-1] == "/files/complete"
    assert not any(t.name == "dfsha-upload-keepalive" for t in threading.enumerate())


def test_put_aborts_without_publish_when_background_renewal_fails(monkeypatch, tmp_path):
    client = DFShaClient("https://unused")
    src = tmp_path / "input"
    src.write_bytes(b"data")
    failed = threading.Event()
    requests = []

    def request(method, path, **kwargs):
        requests.append(path)
        if path == "/files/init":
            return _plan()
        if path == "/files/renew":
            failed.set()
            raise DFShaError("permiso revocado", status=403)
        if path == "/files/abort":
            return {"ok": True}
        pytest.fail(f"no debe publicar tras perder el permiso: {path}")

    def write(block, data, ca):
        assert failed.wait(2)
        return {"block_id": block["block_id"], "checksum": hashlib.sha256(data).hexdigest(), "written": ["n1"]}

    monkeypatch.setattr(client, "_request", request)
    monkeypatch.setattr(client, "_write_block", write)
    with pytest.raises(DFShaError, match="revocado"):
        client.put(str(src), "/u/existing")
    assert requests[-1] == "/files/abort"
    assert "/files/complete" not in requests
    assert not any(t.name == "dfsha-upload-keepalive" for t in threading.enumerate())


def test_get_retains_snapshot_and_refreshes_expired_read_tokens(monkeypatch, tmp_path):
    """usa el cliente y el handle reales, con el plano de datos y el de control simulados"""
    client = DFShaClient("https://unused")
    handles, requests = set(), []
    old = [bytes([i]) * 4 for i in range(PARALLEL_BLOCKS * 2 + 3)]
    old_ids = {str(i) for i in range(len(old))}
    replaced = threading.Event()
    lock = threading.Lock()

    def info(token="expired"):
        return {"handle": "reader", "size": sum(map(len, old)), "version": 1,
                "block_size": 4, "lease_ttl": 60, "allocated_replicas": {},
                "blocks": [{"block_id": str(i), "index": i, "size": len(data),
                            "checksum": hashlib.sha256(data).hexdigest(), "replicas": ["n1:6000"],
                            "token": token} for i, data in enumerate(old)]}

    def request(method, path, **kwargs):
        requests.append(path)
        if path == "/fs/open":
            handles.add("reader")
            return info()
        if path == "/fs/resolve":
            assert "reader" in handles
            return info("fresh")
        if path == "/fs/close":
            handles.remove("reader")
            return {"ok": True}
        if path == "/files/u/file":  # camino viejo: sin retención de snapshot
            return info()
        pytest.fail(f"petición inesperada: {path}")

    def read(block, ca):
        with lock:
            if not replaced.is_set():
                # simula el gc de la versión reemplazada: solo la retiene un handle vivo
                if not handles:
                    old_ids.clear()
                replaced.set()
            if block["block_id"] not in old_ids:
                raise DFShaError("versión anterior liberada")
            if block["token"] == "expired":
                raise DFShaError("token caducado")
            return old[int(block["block_id"])]

    sizes = []
    real_read = DFShaFile.read

    def bounded_read(file, n=-1):
        sizes.append(n)
        return real_read(file, n)

    monkeypatch.setattr(client, "_request", request)
    monkeypatch.setattr(DFShaClient, "_read_block", staticmethod(read))
    monkeypatch.setattr(DFShaFile, "read", bounded_read)
    dst = tmp_path / "output"
    client.get("/u/file", str(dst))
    assert dst.read_bytes() == b"".join(old)
    assert "/fs/resolve" in requests
    assert not handles
    assert all(n == 4 * PARALLEL_BLOCKS * 2 for n in sizes)
    assert not dst.with_name(dst.name + ".part").exists()


def test_failed_get_closes_snapshot_and_preserves_existing_local_file(monkeypatch, tmp_path):
    client = DFShaClient("https://unused")
    requests = []

    def request(method, path, **kwargs):
        requests.append(path)
        if path == "/fs/open":
            return {"handle": "reader", "size": 4, "version": 1, "block_size": 4,
                    "lease_ttl": 60, "blocks": []}
        if path == "/fs/close":
            return {"ok": True}
        pytest.fail(f"petición inesperada: {path}")

    def unavailable(file, n=-1):
        raise DFShaError("sin réplicas disponibles")

    monkeypatch.setattr(client, "_request", request)
    monkeypatch.setattr(DFShaFile, "read", unavailable)
    dst = tmp_path / "output"
    dst.write_bytes(b"conservar")
    with pytest.raises(DFShaError, match="sin réplicas"):
        client.get("/u/file", str(dst))
    assert dst.read_bytes() == b"conservar"
    assert requests[-1] == "/fs/close"
    assert not dst.with_name(dst.name + ".part").exists()


@pytest.mark.integration
@pytest.mark.usefixtures("cluster_up")
def test_get_snapshot_survives_concurrent_overwrite(user, tmp_path, monkeypatch):
    """cluster real: sobrescribir justo después de abrir la descarga conserva la versión vieja"""
    path = f"{user.home}/download-snapshot.bin"
    source = tmp_path / "source"
    original = b"old version" * 100_000
    source.write_bytes(original)
    user.put(str(source), path, block_size=64 * 1024)
    original_open = user.open

    def replace_after_open(remote, mode="r", **kwargs):
        handle = original_open(remote, mode, **kwargs)
        source.write_bytes(b"new version")
        user.put(str(source), path, block_size=64 * 1024)
        return handle

    monkeypatch.setattr(user, "open", replace_after_open)
    output = tmp_path / "output"
    user.get(path, str(output))
    assert output.read_bytes() == original
