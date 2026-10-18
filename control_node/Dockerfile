FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py access.py auth_routes.py cluster.py config.py storage.py dfsha_security.py \
     dfsha_pb2.py dfsha_pb2_grpc.py entrypoint.sh ./

VOLUME ["/data"]

CMD ["sh", "/app/entrypoint.sh"]
