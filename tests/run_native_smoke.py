"""smoke con seis procesos reales y tls/mtls, no necesita docker ni cambia el paquete (python tests/run_native_smoke.py, necesita tests/requirements.txt), crea datos, certificados y logs locales en .native-test/run-* (fuera de git) y raft usa puertos distintos porque cluster.py enlaza 0.0.0.0 en cada proceso"""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback

sys.dont_write_bytecode = True

PROJECT = Path(__file__).resolve().parents[1]
NATIVE = Path(os.environ.get("DFSHA_SMOKE_DIR", str(PROJECT / ".native-test"))).resolve()
RUN = NATIVE / ("run-" + time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3))
CERTS = NATIVE / "certs"
CONTROL_IPS = ["127.0.0.11", "127.0.0.12", "127.0.0.13"]
URLS = [f"https://{ip}:18000" for ip in CONTROL_IPS]
RAFT_ADDRS = [f"{ip}:{14321 + i}" for i, ip in enumerate(CONTROL_IPS)]
TTL = 6
PROCESSES = {}
LOGS = []
RESULTS = []
STOP_LOCK = threading.Lock()
PRINT_LOCK = threading.Lock()
CREATE_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def emit(status, test, **details):
    record = {"status": status, "test": test, **details}
    with PRINT_LOCK:
        RESULTS.append(record)
        print(json.dumps(record, ensure_ascii=False), flush=True)
        (RUN / "results.json").write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False), encoding="utf-8")


def stop_one(name):
    p = PROCESSES[name]
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)


def cleanup():
    with STOP_LOCK:
        for name in reversed(list(PROCESSES)):
            try:
                stop_one(name)
            except Exception:
                pass


def watchdog():
    emit("FAIL", "total_timeout", seconds=300)
    cleanup()
    os._exit(2)


def check_ports():
    addresses = [(ip, 18000) for ip in CONTROL_IPS]
    addresses += [("0.0.0.0", 14321 + i) for i in range(3)]
    addresses += [("0.0.0.0", base + i) for base in (16001, 16101) for i in range(3)]
    for addr in addresses:
        with socket.socket() as s:
            s.bind(addr)  # si el puerto está ocupado se aborta, nunca se mata un proceso ajeno


def start(name, command, cwd, environment):
    log = (RUN / f"{name}.log").open("wb")
    LOGS.append(log)
    PROCESSES[name] = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT, creationflags=CREATE_FLAGS)


def wait_until(description, predicate, timeout=60, interval=0.3):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except Exception as error:
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(interval)
    raise TimeoutError(f"{description}; último error: {last_error}")


def run_case(name, fn):
    began = time.monotonic()
    try:
        detail = fn() or {}
    except Exception as error:
        emit("FAIL", name, error=f"{type(error).__name__}: {error}", seconds=round(time.monotonic() - began, 2))
        raise
    emit("PASS", name, seconds=round(time.monotonic() - began, 2), **detail)


def main():
    RUN.mkdir(parents=True)
    check_ports()
    # el secreto cambia en cada ejecución y los directorios de datos también, no se imprime ni se escribe en .env
    cluster_secret, admin_password = secrets.token_hex(32), secrets.token_urlsafe(24)
    environment = dict(os.environ)
    no_proxy = ",".join(["localhost", "127.0.0.1", "::1", *CONTROL_IPS])
    environment.update(NO_PROXY=no_proxy, no_proxy=no_proxy, CLUSTER_SECRET=cluster_secret,
                       ADMIN_PASSWORD=admin_password, PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1",
                       TLS_CA=str(CERTS / "ca.crt"), REPLICATION_FACTOR="2", MIN_REPLICAS="2",
                       UPLOAD_TTL=str(TTL), BLOCK_TOKEN_TTL=str(TTL), HANDLE_TTL="12",
                       HEARTBEAT_INTERVAL="1", BLOCK_REPORT_INTERVAL="2", HEARTBEAT_TIMEOUT="5",
                       REREPLICATE_AFTER="7", MONITOR_INTERVAL="1", WARMUP="2", ORPHAN_MIN_AGE="2",
                       SCRUB_INTERVAL="0", API_PORT="18000", DFSHA_RETRY_SECONDS="20")
    # no heredar claves ni topología de otras instalaciones
    environment.pop("DATA_KEY", None)
    environment.pop("DFSHA_ADDRESS_MAP", None)
    names = [f"native-control{i}" for i in range(1, 4)] + [f"native-data{i}" for i in range(1, 4)]
    certificate_command = [sys.executable, str(PROJECT / "scripts" / "gen_certs.py"), "--out", str(CERTS)]
    for name in names:
        certificate_command += ["--name", name]
    for ip in CONTROL_IPS:
        certificate_command += ["--san", ip]
    with (RUN / "certificates.log").open("wb") as log:
        subprocess.run(certificate_command, cwd=RUN, env=environment, check=True, timeout=30,
                       stdout=log, stderr=subprocess.STDOUT, creationflags=CREATE_FLAGS)

    timer = threading.Timer(300, watchdog)
    timer.daemon = True
    timer.start()
    try:
        for i, ip in enumerate(CONTROL_IPS):
            name = f"native-control{i + 1}"
            env = dict(environment, DATA_DIR=str(RUN / name), RAFT_SELF=RAFT_ADDRS[i],
                       RAFT_PEERS=",".join(a for j, a in enumerate(RAFT_ADDRS) if j != i),
                       TLS_CERT=str(CERTS / f"{name}.crt"), TLS_KEY=str(CERTS / f"{name}.key"))
            command = [sys.executable, "-m", "uvicorn", "app:app", "--host", ip, "--port", "18000",
                       "--ssl-keyfile", env["TLS_KEY"], "--ssl-certfile", env["TLS_CERT"], "--log-level", "warning"]
            start(name, command, PROJECT / "control_node", env)
        for i in range(3):
            name = f"native-data{i + 1}"
            env = dict(environment, NODE_ID=name, DATA_DIR=str(RUN / name),
                       GRPC_PORT=str(16001 + i), INTERNAL_GRPC_PORT=str(16101 + i),
                       NODE_ADDR=f"localhost:{16001 + i}", INTERNAL_ADDR=f"localhost:{16101 + i}",
                       CONTROL_NODE_URLS=",".join(URLS),
                       TLS_CERT=str(CERTS / f"{name}.crt"), TLS_KEY=str(CERTS / f"{name}.key"))
            start(name, [sys.executable, "server.py"], PROJECT / "data_node", env)

        os.environ.update(NO_PROXY=no_proxy, no_proxy=no_proxy, DFSHA_CA_CERT=str(CERTS / "ca.crt"),
                          DFSHA_RETRY_SECONDS="20")
        os.environ.pop("DFSHA_ADDRESS_MAP", None)
        sys.path.insert(0, str(PROJECT / "client"))
        import requests
        from dfsha_client import DFShaClient
        http = requests.Session()
        http.trust_env = False
        http.verify = str(CERTS / "ca.crt")

        def leader():
            for i, url in enumerate(URLS):
                if PROCESSES[f"native-control{i + 1}"].poll() is not None:
                    continue
                try:
                    response = http.get(url + "/raft/status", timeout=1)
                    if response.ok and response.json().get("can_serve"):
                        return i, response.json()
                except requests.RequestException:
                    pass
            return None

        def ready():
            current = leader()
            if current is None:
                return None
            for url in URLS:
                response = http.get(url + "/health", timeout=2)
                if not response.ok or response.json().get("datanodes_alivos", 0) < 3:
                    return None
            return current

        def startup():
            wait_until("3 ControlNodes + 3 DataNodes TLS listos", ready)
            assert all(p.poll() is None for p in PROCESSES.values())
            return {"processes": 6, "tls": True, "raft_ports": [14321, 14322, 14323]}

        run_case("native_cluster_startup", startup)
        client = DFShaClient(URLS, ca_cert=str(CERTS / "ca.crt"))
        username, password = "smoke_" + secrets.token_hex(4), secrets.token_urlsafe(18)
        client.register(username, password)
        client.login(username, password)
        home = "/" + username
        local = RUN / "source.bin"
        output = RUN / "output.bin"
        baseline = secrets.token_bytes(16 * 65536 + 37)
        remote = home + "/baseline.bin"

        def roundtrip():
            local.write_bytes(baseline)
            client.put(str(local), remote, block_size=65536)
            client.get(remote, str(output))
            assert output.read_bytes() == baseline
            meta = client._request("GET", "/files" + remote)
            holders = {address for block in meta["blocks"] for address in block["replicas"]}
            assert len(meta["blocks"]) == 17 and len(holders) >= 2
            return {"bytes": len(baseline), "blocks": len(meta["blocks"]), "nodes": len(holders)}

        run_case("put_get_multiblock", roundtrip)

        def random_access():
            patch = b"RF3 update across a block boundary"
            expected = bytearray(baseline)
            expected[65530:65530 + len(patch)] = patch
            with client.open(remote, "r+", lock="exclusive") as file:
                file.seek(65530)
                file.write(patch)
            client.get(remote, str(output))
            assert output.read_bytes() == bytes(expected)
            # restaura el archivo base para las siguientes pruebas
            local.write_bytes(baseline)
            client.put(str(local), remote, block_size=65536)
            return {"cross_block_update": True}

        run_case("rf3_partial_write", random_access)

        def snapshot_overwrite():
            real_open = client.open
            def open_then_replace(path, mode="r", **kwargs):
                handle = real_open(path, mode, **kwargs)
                try:
                    local.write_bytes(b"replacement")
                    client.put(str(local), remote, block_size=65536)
                except BaseException:
                    handle.close(discard=True)
                    raise
                return handle
            client.open = open_then_replace
            try:
                client.get(remote, str(output))
            finally:
                client.open = real_open
            assert output.read_bytes() == baseline
            return {"snapshot_survived_overwrite": True}

        run_case("get_concurrent_overwrite", snapshot_overwrite)

        slow_path = home + "/long-transfer.bin"
        slow_data = secrets.token_bytes(16 * 65536)
        def long_transfers():
            real_write = client._write_block
            def slow_write(block, data, ca=None):
                time.sleep(2.2)
                return real_write(block, data, ca)
            local.write_bytes(slow_data)
            client._write_block = slow_write
            began = time.monotonic()
            try:
                client.put(str(local), slow_path, block_size=65536)
            finally:
                client._write_block = real_write
            upload_seconds = time.monotonic() - began
            assert upload_seconds > TTL
            real_open = client.open
            def open_then_wait(path, mode="r", **kwargs):
                handle = real_open(path, mode, **kwargs)
                time.sleep(TTL + 1)  # vencen los tokens originales, el handle sigue vivo
                return handle
            client.open = open_then_wait
            try:
                client.get(slow_path, str(output))
            finally:
                client.open = real_open
            assert output.read_bytes() == slow_data
            return {"ttl_seconds": TTL, "upload_seconds": round(upload_seconds, 2),
                    "download_initial_tokens_expired": True}

        run_case("transfer_beyond_token_and_upload_ttl", long_transfers)

        def failover():
            old_index, old_status = wait_until("líder antes del fallo", leader, timeout=10)
            killed = f"native-control{old_index + 1}"
            began = time.monotonic()
            stop_one(killed)
            new_index, new_status = wait_until("elección después de detener líder", leader, timeout=45)
            assert new_index != old_index
            local.write_bytes(b"write after leader failover")
            target = home + "/after-failover.bin"
            client.put(str(local), target, block_size=65536)
            client.get(target, str(output))
            assert output.read_bytes() == local.read_bytes()
            client.get(slow_path, str(output))
            assert output.read_bytes() == slow_data
            return {"stopped": killed, "new_leader": new_status["self"],
                    "recovery_seconds": round(time.monotonic() - began, 2)}

        run_case("leader_failure_read_write", failover)

        def disk_loss_repair():
            # borra solo bloques creados por este script, en uno de sus datanodes
            live_meta = client._request("GET", "/files" + slow_path)
            live_ids = {b["block_id"] for b in live_meta["blocks"]}
            node = max((f"native-data{i}" for i in range(1, 4)),
                       key=lambda name: sum((RUN / name / (bid + ".blk")).is_file() for bid in live_ids))
            data_dir = (RUN / node).resolve()
            assert data_dir.is_relative_to(RUN.resolve())
            blocks = list(data_dir.glob("*.blk"))
            relevant = [b for b in blocks if b.stem in live_ids]
            assert relevant, "el nodo elegido no tenía bloques del archivo de prueba"
            for block in blocks:
                block.unlink()
            assert PROCESSES[node].poll() is None, "la prueba requiere que el nodo siga enviando heartbeat"
            # no basta con contar metadatos: comprueba dos copias físicas de cada bloque activo
            def repaired():
                meta = client._request("GET", "/files" + slow_path)
                return all(sum((RUN / f"native-data{i}" / (b["block_id"] + ".blk")).is_file()
                               for i in range(1, 4)) >= 2 for b in meta["blocks"])
            wait_until("reparación de copias ausentes en nodo vivo", repaired, timeout=45, interval=0.5)
            client.get(slow_path, str(output))
            assert output.read_bytes() == slow_data
            return {"live_node": node, "deleted_files": len(blocks), "deleted_active_blocks": len(relevant),
                    "replicas_verified_on_disk": 2}

        run_case("live_datanode_disk_loss_repair", disk_loss_repair)
        emit("PASS", "native_smoke_complete", log_directory=str(RUN), cases=7)
        return 0
    finally:
        timer.cancel()
        cleanup()
        for log in LOGS:
            log.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        if RUN.exists():
            (RUN / "failure.txt").write_text(traceback.format_exc(), encoding="utf-8")
            emit("FAIL", "native_smoke_aborted", error=f"{type(error).__name__}: {error}", log_directory=str(RUN))
        else:
            print(json.dumps({"status": "FAIL", "test": "setup", "error": str(error)}), flush=True)
        raise SystemExit(1)
