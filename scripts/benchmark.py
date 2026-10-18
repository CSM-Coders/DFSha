#!/usr/bin/env python3
"""mide el rendimiento del cluster local (docker compose) y escribe tablas en markdown listas para el informe: python scripts/benchmark.py (completo, 3-5 min), --quick (tamaños pequeños), --ha (además mide el failover del líder y la re-replicación, detiene contenedores) y --json resultados.json; necesita el cluster levantado (scripts/start.sh) y `pip install -r client/requirements.txt`"""
import argparse
import json
import os
import random
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
os.environ.setdefault("DFSHA_CA_CERT", str(ROOT / "certs" / "ca.crt"))

import requests  # noqa: E402

import dfsha_client  # noqa: E402
from dfsha_client import DFShaClient  # noqa: E402

MB = 1024 * 1024
CONTROL_PORTS = {"control1": 8001, "control2": 8002, "control3": 8003}
results: dict = {}


def new_user() -> DFShaClient:
    c = DFShaClient()
    name = "bench" + uuid.uuid4().hex[:8]
    c.register(name, "secret123")
    c.login(name, "secret123")
    return c


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p / 100))]


def table(title, header, rows):
    print(f"\n### {title}\n")
    print("| " + " | ".join(header) + " |")
    print("|" + "|".join("-" for _ in header) + "|")
    for r in rows:
        print("| " + " | ".join(str(x) for x in r) + " |")
    results[title] = {"header": header, "rows": rows}


def timed(fn):
    t = time.perf_counter()
    fn()
    return time.perf_counter() - t


def compose(*args):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True)


def bench_metadata(c, n):
    h = c.home if hasattr(c, "home") else "/" + c.username
    c.mkdir(f"{h}/m")
    c.open(f"{h}/m/f", "w").close()
    ops = {
        "mkdir (escritura Raft)": lambda i: c.mkdir(f"{h}/m/d{i}"),
        "stat (lectura local)": lambda i: c.stat(f"{h}/m/f"),
        "ls de 1 directorio": lambda i: c.ls(f"{h}/m"),
        "crear archivo vacío (open+commit)": lambda i: c.open(f"{h}/m/e{i}", "w").close(),
    }
    rows = []
    for name, op in ops.items():
        ts = [timed(lambda i=i: op(i)) * 1000 for i in range(n)]
        rows.append([name, f"{statistics.median(ts):.1f}", f"{pct(ts, 95):.1f}", f"{n}"])
    table("Latencia de operaciones de metadatos (ms)", ["operación", "mediana", "p95", "muestras"], rows)


def bench_throughput(c, size_mb, block_sizes, parallels):
    data = os.urandom(size_mb * MB)
    rows = []
    with tempfile.TemporaryDirectory() as d:
        src, dst = os.path.join(d, "src"), os.path.join(d, "dst")
        open(src, "wb").write(data)
        for bs in block_sizes:
            for par in parallels:
                dfsha_client.PARALLEL_BLOCKS = par
                path = f"/{c.username}/t_{bs}_{par}.bin"
                tp = timed(lambda: c.put(src, path, block_size=bs * MB))
                tg = timed(lambda: c.get(path, dst))
                assert open(dst, "rb").read(1024) == data[:1024]
                rows.append([f"{bs} MiB", par, f"{size_mb / tp:.1f}", f"{size_mb / tg:.1f}"])
                c.rm(path)
    dfsha_client.PARALLEL_BLOCKS = 4
    table(f"Rendimiento de un cliente con un archivo de {size_mb} MiB (MiB/s, RF=2, TLS + AES-GCM)",
          ["tamaño de bloque", "bloques en paralelo", "put", "get"], rows)


def bench_concurrency(clients_list, size_mb):
    rows = []
    for n in clients_list:
        cs = [new_user() for _ in range(n)]
        data = os.urandom(size_mb * MB)
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "s")
            open(src, "wb").write(data)
            barrier = threading.Barrier(n)

            def work(c):
                barrier.wait()
                c.put(src, f"/{c.username}/c.bin")

            t = time.perf_counter()
            with ThreadPoolExecutor(n) as pool:
                list(pool.map(work, cs))
            elapsed = time.perf_counter() - t
        rows.append([n, f"{n * size_mb / elapsed:.1f}", f"{elapsed:.1f}"])
        for c in cs:
            c.rm(f"/{c.username}/c.bin")
    table(f"Escalado con clientes concurrentes (cada uno sube {size_mb} MiB)", ["clientes", "MiB/s agregados", "segundos"], rows)


def bench_random_access(c, file_mb, ops):
    path = f"/{c.username}/ra.bin"
    with c.open(path, "w", block_size=4 * MB) as f:
        for _ in range(file_mb):
            f.write(os.urandom(MB))
    rng = random.Random(1)

    def cold_read():
        with c.open(path, "r") as f:
            f.seek(rng.randrange(0, file_mb * MB - 4096))
            f.read(4096)

    cold = [timed(cold_read) * 1000 for _ in range(ops)]
    with c.open(path, "r") as f:
        f.seek(0)
        f.read(4096)  # el bloque ya está en la caché del cliente
        warm = []
        for i in range(ops):
            f.seek(4096 * (i % 500))
            warm.append(timed(lambda: f.read(4096)) * 1000)

    def write_patch():
        with c.open(path, "r+") as f:
            f.seek(rng.randrange(0, file_mb * MB - 4096))
            f.write(b"x" * 4096)  # open + escribir 4 kib + commit (reescribe 1 bloque)

    patch = [timed(write_patch) * 1000 for _ in range(max(5, ops // 5))]
    table(f"Acceso aleatorio en un archivo de {file_mb} MiB (bloques de 4 MiB), ms",
          ["operación", "mediana", "p95"],
          [["leer 4 KiB, sesión nueva (descarga 1 bloque)", f"{statistics.median(cold):.1f}", f"{pct(cold, 95):.1f}"],
           ["leer 4 KiB con el bloque ya en caché", f"{statistics.median(warm):.2f}", f"{pct(warm, 95):.2f}"],
           ["actualizar 4 KiB y publicar (copy-on-write de 1 bloque)", f"{statistics.median(patch):.1f}", f"{pct(patch, 95):.1f}"]])
    c.rm(path)


def leader():
    for name, port in CONTROL_PORTS.items():
        try:
            st = requests.get(f"https://localhost:{port}/raft/status", timeout=2, verify=os.environ["DFSHA_CA_CERT"]).json()
            if st.get("can_serve"):
                return name
        except requests.RequestException:
            pass
    return None


def bench_ha(c):
    rows = []
    for rnd in range(3):
        lead = leader()
        t0 = time.perf_counter()
        compose("stop", lead)
        done = None
        while time.perf_counter() - t0 < 60:
            try:
                c.mkdir(f"/{c.username}/ha{rnd}")
                done = time.perf_counter() - t0
                break
            except Exception:
                time.sleep(0.2)
        rows.append([f"{rnd + 1}", lead, leader(), f"{done:.1f}" if done else "no se recuperó"])
        compose("start", lead)
        time.sleep(10)
    table("Failover del ControlNode líder: tiempo hasta que las escrituras vuelven a funcionar",
          ["ronda", "líder detenido", "nuevo líder", "segundos"], rows)

    path = f"/{c.username}/rr.bin"
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "s")
        open(src, "wb").write(os.urandom(48 * MB))
        c.put(src, path, block_size=4 * MB)
    victim = "datanode3"
    t0 = time.perf_counter()
    compose("stop", victim)
    healed, lost_seen = None, False
    while time.perf_counter() - t0 < 180:
        blocks = c._request("GET", f"/files{path}")["blocks"]
        counts = [len(b["replicas"]) for b in blocks]
        lost_seen |= min(counts) < 2
        if lost_seen and min(counts) >= 2:
            healed = time.perf_counter() - t0
            break
        time.sleep(1)
    table("Re-replicación tras detener un DataNode (12 bloques de 4 MiB, RF=2)",
          ["evento", "segundos"],
          [["DataNode detenido → todos los bloques vuelven a tener 2 réplicas", f"{healed:.1f}" if healed else "no se recuperó"]])
    compose("start", victim)
    c.rm(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--ha", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()
    c = new_user()
    print(f"# Resultados de rendimiento de DFSha ({time.strftime('%Y-%m-%d %H:%M')})")
    print("\nCluster: 3 ControlNodes (Raft) + 3 DataNodes en Docker, RF=2, TLS en todos los canales, "
          "bloques cifrados con AES-256-GCM en reposo. Cliente en la misma máquina.")
    bench_metadata(c, 30 if a.quick else 100)
    bench_throughput(c, 16 if a.quick else 64, [1, 4] if a.quick else [1, 4, 16], [1, 4] if a.quick else [1, 4, 8])
    bench_concurrency([1, 2, 4] if a.quick else [1, 2, 4, 8], 8 if a.quick else 32)
    bench_random_access(c, 16 if a.quick else 64, 20 if a.quick else 50)
    if a.ha:
        bench_ha(c)
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
