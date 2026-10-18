"""replica los metadatos entre los control nodes con raft (pysyncobj): todo cambio pasa por `Cluster.write`, se manda a la mayoría y se aplica igual en cada nodo; las lecturas son locales y un líder solo atiende después de confirmar la barrera `noop`"""
import os
import time
import logging
import threading
from typing import Optional

from pysyncobj import SyncObj, SyncObjConf, SyncObjConsumer, SyncObjException, replicated

import storage

log = logging.getLogger("cluster")

WRITE_TIMEOUT = float(os.environ.get("RAFT_WRITE_TIMEOUT", "10"))


class Unavailable(Exception):
    """el cluster no puede confirmar la escritura (sin líder o sin quórum)"""


class _StateMachine(SyncObjConsumer):
    def _serialize(self):
        return {"db": storage.dump()}

    def _deserialize(self, data):
        storage.load(data["db"])

    @replicated
    def apply(self, op, kw):
        # tiene que ser determinista y no lanzar errores, si falla aquí los nodos se desincronizan
        try:
            return ("ok", storage.OPS[op](**kw))
        except (storage.Locked, storage.Conflict, storage.Gone) as e:
            return ("err", type(e).__name__, str(e))
        except Exception as e:  # noqa: BLE001
            log.exception("operación %s falló al aplicarse", op)
            return ("err", "Internal", f"{type(e).__name__}: {e}")


class Cluster:
    def __init__(self):
        self._sync: Optional[SyncObj] = None
        self._sm: Optional[_StateMachine] = None
        self._barrier_term = None
        self._stop = threading.Event()
        self.self_addr = ""

    # ciclo de vida

    def start(self, self_addr: str, peers: list[str], data_dir: str, password: Optional[str] = None):
        os.makedirs(data_dir, exist_ok=True)
        storage.init_db()
        self.self_addr = self_addr
        conf = SyncObjConf(
            autoTick=True,
            bindAddress=f"0.0.0.0:{self_addr.rsplit(':', 1)[1]}",
            journalFile=os.path.join(data_dir, "raft.journal"),
            fullDumpFile=os.path.join(data_dir, "raft.dump"),
            dynamicMembershipChange=False,
            appendEntriesPeriod=float(os.environ.get("RAFT_APPEND_PERIOD", "0.02")),
            appendEntriesUseBatch=False,  # manda cada entrada de una vez (menos latencia) en vez de esperar al periodo
            autoTickPeriod=0.01,
            leaderFallbackTimeout=float(os.environ.get("RAFT_LEADER_FALLBACK", "5")),  # un líder sin mayoría deja de serlo (por defecto 30 s)
            raftMinTimeout=float(os.environ.get("RAFT_MIN_TIMEOUT", "0.5")),
            raftMaxTimeout=float(os.environ.get("RAFT_MAX_TIMEOUT", "1.2")),
            logCompactionMinEntries=int(os.environ.get("RAFT_COMPACT_ENTRIES", "2000")),
            password=password,
            # los nodos se identifican por la ip de su hostname y con la caché por defecto (600 s) un contenedor que cambia de ip se confunde con otro nodo
            dnsCacheTime=float(os.environ.get("RAFT_DNS_CACHE", "5")),
            dnsFailCacheTime=2.0,
        )
        self._sm = _StateMachine()
        self._sync = SyncObj(self_addr, peers, conf=conf, consumers=[self._sm])
        threading.Thread(target=self._barrier_loop, daemon=True, name="raft-barrier").start()
        log.info("Raft iniciado: yo=%s pares=%s", self_addr, peers)

    def stop(self):
        self._stop.set()
        if self._sync:
            self._sync.destroy()

    # estado

    @property
    def started(self) -> bool:
        return self._sync is not None

    def is_leader(self) -> bool:
        return self.started and self._sync._isLeader()

    def can_serve(self) -> bool:
        """líder que ya confirmó su barrera y tiene contacto con la mayoría, sus lecturas locales valen"""
        return (self.is_leader() and self._barrier_term == self._sync._getTerm()
                and self._sync.hasQuorum)

    def leader_host(self) -> Optional[str]:
        leader = self._sync._getLeader() if self.started else None
        return getattr(leader, "host", None) if leader else None

    def status(self) -> dict:
        if not self.started:
            return {}
        st = dict(self._sync.getStatus())
        leader = st.get("leader")
        return {
            "self": self.self_addr,
            "leader": str(leader) if leader else None,
            "is_leader": self.is_leader(),
            "can_serve": self.can_serve(),
            "term": st.get("raft_term"),
            "commit_idx": st.get("commit_idx"),
            "last_applied": st.get("last_applied"),
            "log_len": st.get("log_len"),
            "partners": st.get("partner_nodes_count"),
            "has_quorum": st.get("has_quorum"),
            "ready": self._sync.isReady(),
        }

    def _barrier_loop(self):
        while not self._stop.wait(0.1):
            try:
                if not self.is_leader():
                    self._barrier_term = None
                    continue
                term = self._sync._getTerm()
                if self._barrier_term != term:
                    self.write("noop")
                    if self._sync._isLeader() and self._sync._getTerm() == term:
                        self._barrier_term = term
                        log.info("líder en el término %s: barrera confirmada, sirviendo", term)
            except Exception:  # noqa: BLE001
                time.sleep(0.5)

    # escritura

    def write(self, op: str, **kw):
        """replica y aplica una operación de storage.OPS, devuelve su resultado o lanza el error que corresponda (Locked/Conflict/Gone)"""
        if not self.started:
            raise Unavailable("cluster no iniciado")
        try:
            res = self._sm.apply(op, kw, sync=True, timeout=WRITE_TIMEOUT)
        except SyncObjException as e:
            raise Unavailable(f"sin quórum o sin líder: {e}") from e
        if res[0] == "ok":
            return res[1]
        _, name, msg = res
        exc = {"Locked": storage.Locked, "Conflict": storage.Conflict, "Gone": storage.Gone}.get(name)
        if exc:
            raise exc(msg)
        raise RuntimeError(f"{name}: {msg}")


cluster = Cluster()
