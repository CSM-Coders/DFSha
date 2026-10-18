#!/bin/sh
# arranca el control node, si hay TLS_CERT y TLS_KEY sirve la api rest por https
set -e
ARGS=""
if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
  ARGS="--ssl-keyfile $TLS_KEY --ssl-certfile $TLS_CERT"
fi
exec uvicorn app:app --host 0.0.0.0 --port "${API_PORT:-8000}" $ARGS
