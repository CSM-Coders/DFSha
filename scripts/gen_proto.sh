#!/usr/bin/env bash
# regenera dfsha_pb2.py y dfsha_pb2_grpc.py desde proto/dfsha.proto, los copia a cada componente y copia también common/dfsha_security.py (cada dockerfile solo ve su propia carpeta), necesita pip install grpcio-tools==1.84.0
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
OUT="$(mktemp -d)"
"$PY" -m grpc_tools.protoc -I proto --python_out="$OUT" --grpc_python_out="$OUT" proto/dfsha.proto

for d in client control_node data_node; do
  cp "$OUT/dfsha_pb2.py" "$OUT/dfsha_pb2_grpc.py" "$d/"
done
rm -rf "$OUT"
# módulo de seguridad compartido (cada dockerfile solo ve su propia carpeta)
for d in control_node data_node; do
  cp common/dfsha_security.py "$d/"
done
echo "Código gRPC regenerado en client/, control_node/ y data_node/; dfsha_security.py copiado a control_node/ y data_node/"
