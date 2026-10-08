FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dfsha_pb2.py dfsha_pb2_grpc.py server.py ./

VOLUME ["/data"]

CMD ["python", "server.py"]
