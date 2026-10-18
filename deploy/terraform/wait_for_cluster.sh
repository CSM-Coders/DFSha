#!/usr/bin/env bash
# espera hasta 10 min a que el cluster esté sano, uso: wait_for_cluster.sh <ca.crt> <datanodes_esperados> <ip_control> [<ip_control> ...]
set -u
CA="$1"; EXPECTED="$2"; shift 2

check() {
  curl -fsS --max-time 5 --cacert "$CA" "https://$1:8000/health" 2>/dev/null | python3 -c '
import json, sys
h = json.load(sys.stdin)
ok = h.get("ok") and h["raft"].get("leader") and h["raft"].get("has_quorum") and h.get("datanodes_alivos", 0) >= int(sys.argv[1])
print(h["raft"].get("leader"), h.get("datanodes_alivos"))
sys.exit(0 if ok else 1)' "$EXPECTED"
}

for _ in $(seq 1 60); do
  for ip in "$@"; do
    if out=$(check "$ip"); then
      echo "Cluster sano (vía $ip): líder/datanodes = $out"
      exit 0
    fi
  done
  sleep 10
done
echo "El cluster no quedó sano en 10 min; revisa con ssh y 'sudo docker compose logs' en las VMs." >&2
exit 1
