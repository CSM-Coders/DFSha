"""
DataNode: almacena bloques físicos en disco local y los expone vía gRPC.
Se registra periódicamente (heartbeat) ante el ControlNode para que este
sepa qué nodos están vivos y pueda asignarles bloques.
"""
import os
import time
import hashlib
import logging
import threading
from concurrent import futures

import grpc
import requests

import dfsha_pb2
import dfsha_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("datanode")

NODE_ID = os.environ.get("NODE_ID", "datanode-unknown")
NODE_ADDR = os.environ.get("NODE_ADDR", "localhost:6000")  # host:puerto por el que el CLIENTE lo contacta (fuera de Docker)
INTERNAL_ADDR = os.environ.get("INTERNAL_ADDR", NODE_ADDR)  # host:puerto por el que el ControlNode lo contacta (dentro de la red de Docker)
DATA_DIR = os.environ.get("DATA_DIR", "/data")
CONTROL_NODE_URL = os.environ.get("CONTROL_NODE_URL", "http://control_node:8000")
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "5"))
GRPC_PORT = os.environ.get("GRPC_PORT", "6000")

os.makedirs(DATA_DIR, exist_ok=True)


def _block_path(block_id: str) -> str:
    # Evita path traversal: solo el nombre base del block_id.
    safe_id = os.path.basename(block_id)
    return os.path.join(DATA_DIR, safe_id + ".blk")


class DataNodeServicer(dfsha_pb2_grpc.DataNodeServicer):

    def WriteBlock(self, request, context):
        try:
            checksum = hashlib.sha256(request.data).hexdigest()
            if request.checksum and request.checksum != checksum:
                return dfsha_pb2.Ack(success=False, message="checksum mismatch")

            with open(_block_path(request.block_id), "wb") as f:
                f.write(request.data)

            log.info("Bloque %s escrito (%d bytes)", request.block_id, len(request.data))
            return dfsha_pb2.Ack(success=True, message=checksum)
        except Exception as e:
            log.exception("Error escribiendo bloque %s", request.block_id)
            return dfsha_pb2.Ack(success=False, message=str(e))

    def ReadBlock(self, request, context):
        path = _block_path(request.block_id)
        if not os.path.exists(path):
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"bloque {request.block_id} no existe en este nodo")
            return dfsha_pb2.Block()

        with open(path, "rb") as f:
            data = f.read()
        checksum = hashlib.sha256(data).hexdigest()
        return dfsha_pb2.Block(block_id=request.block_id, data=data, checksum=checksum)

    def DeleteBlock(self, request, context):
        path = _block_path(request.block_id)
        if os.path.exists(path):
            os.remove(path)
        return dfsha_pb2.Ack(success=True, message="deleted")

    def Ping(self, request, context):
        return dfsha_pb2.Ack(success=True, message="pong")


def heartbeat_loop():
    """Se registra periódicamente ante el ControlNode. Si el ControlNode
    está caído o arrancando, reintenta sin tumbar el DataNode."""
    while True:
        try:
            used = sum(
                os.path.getsize(os.path.join(DATA_DIR, f))
                for f in os.listdir(DATA_DIR)
            )
            requests.post(
                f"{CONTROL_NODE_URL}/datanodes/register",
                json={
                    "node_id": NODE_ID,
                    "address": NODE_ADDR,
                    "internal_address": INTERNAL_ADDR,
                    "used_bytes": used,
                },
                timeout=3,
            )
        except Exception as e:
            log.warning("No se pudo hacer heartbeat al ControlNode: %s", e)
        time.sleep(HEARTBEAT_INTERVAL)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    dfsha_pb2_grpc.add_DataNodeServicer_to_server(DataNodeServicer(), server)
    server.add_insecure_port(f"[::]:{GRPC_PORT}")
    server.start()
    log.info("DataNode %s escuchando en :%s (anunciado como %s)", NODE_ID, GRPC_PORT, NODE_ADDR)

    threading.Thread(target=heartbeat_loop, daemon=True).start()

    server.wait_for_termination()


if __name__ == "__main__":
    serve()
