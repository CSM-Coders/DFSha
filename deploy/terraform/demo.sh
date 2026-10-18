# funciones para la demo en aws, se usa con: source deploy/terraform/demo.sh (desde la carpeta del repo)

DFSHA_ROOT="$(git rev-parse --show-toplevel)"
TF_DIR="$DFSHA_ROOT/deploy/terraform"
export GRPC_ENABLE_FORK_SUPPORT=0 GRPC_VERBOSITY=ERROR

# variables del cliente (urls de los control nodes y ca del cluster)
eval "$(terraform -chdir="$TF_DIR" output -raw client_env)"

# cliente: dfsha ls /alice, dfsha put ..., etc
dfsha() { python "$DFSHA_ROOT/client/cli.py" "$@"; }

# ip pública de un nodo (control1..3 o datanode1..3) sacada de terraform
_ip_de() { terraform -chdir="$TF_DIR" output -json ssh | python3 -c "import json,sys; print(json.load(sys.stdin)['$1'].split('@')[-1])"; }

# ssh sin avisos: nodo_ssh control1 'comando'
nodo_ssh() {
  local nodo="$1"; shift
  ssh -i "$TF_DIR/dfsha-lab.pem" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      -o ConnectTimeout=10 "ec2-user@$(_ip_de "$nodo")" "$@"
}

# qué control node es el líder ahora
lider() {
  local n url
  for n in control1 control2 control3; do
    url="https://$(_ip_de $n):8000/raft/status"
    if curl -s --max-time 4 --cacert "$DFSHA_CA_CERT" "$url" | grep -q '"can_serve":true'; then
      echo "$n"; return 0
    fi
  done
  return 1
}

# cuántos bloques guarda cada datanode (para ver cómo se reparten)
bloques_por_nodo() {
  local n
  for n in datanode1 datanode2 datanode3; do
    echo "$n: $(nodo_ssh $n 'sudo docker exec $(sudo docker ps -q) sh -c "ls /data/*.blk | wc -l"') bloques"
  done
}

# muestra un bloque tal como está en el disco de un datanode (cifrado, empieza con DFS2)
bloque_cifrado() {
  nodo_ssh datanode1 'sudo docker exec $(sudo docker ps -q) sh -c "f=\$(ls /data/*.blk | head -1); echo \$f; head -c 64 \$f | od -c | head -4"'
}

# tls: sin la ca del cluster falla y con la ca funciona
tls_sin_ca() { curl -sS --max-time 8 "https://$(_ip_de control1):8000/health"; }
tls_con_ca() { curl -sS --max-time 8 --cacert "$DFSHA_CA_CERT" "https://$(_ip_de control1):8000/health"; echo; }

# mata al líder y mide cuánto tarda en volver a escribir el cluster (necesita haber hecho login)
matar_lider() {
  local viejo t0 t1 nuevo
  viejo="$(lider)" || { echo "no hay líder"; return 1; }
  echo "líder actual: $viejo, lo matamos"
  nodo_ssh "$viejo" 'sudo docker kill $(sudo docker ps -q)' > /dev/null
  t0=$(python3 -c 'import time; print(time.time())')
  until dfsha mkdir "/alice/ha_$RANDOM" > /dev/null 2>&1; do sleep 0.2; done
  t1=$(python3 -c 'import time; print(time.time())')
  nuevo="$(lider)"
  echo "el cluster volvió a escribir en $(python3 -c "print(round($t1 - $t0, 1))") s, nuevo líder: $nuevo"
  echo "$viejo" > "$TF_DIR/.ultimo_caido"
}

# vuelve a levantar el control node que se mató
levantar_control() {
  local n="${1:-$(cat "$TF_DIR/.ultimo_caido")}"
  nodo_ssh "$n" 'cd dfsha/deploy/control && sudo docker compose start' > /dev/null 2>&1 && echo "$n arriba otra vez"
}

# datanodes: parar_datanode datanode3 / levantar_datanode datanode3
parar_datanode() { nodo_ssh "$1" 'cd dfsha/deploy/data && sudo docker compose stop' > /dev/null 2>&1 && echo "$1 detenido"; }
levantar_datanode() { nodo_ssh "$1" 'cd dfsha/deploy/data && sudo docker compose start' > /dev/null 2>&1 && echo "$1 arriba otra vez"; }

# login de admin sin mostrar la contraseña
login_admin() { dfsha login admin "$(terraform -chdir="$TF_DIR" output -raw admin_password)"; }

# deja limpia la cuenta de alice entre ensayos y grabaciones
limpiar_demo() {
  local e
  dfsha login alice alice123 > /dev/null || return 1
  for e in $(dfsha ls /alice | awk '{print $NF}'); do dfsha rm -r "$e" > /dev/null; done
  echo "/alice quedó así:"; dfsha ls /alice
  rm -f "$HOME/.dfsha_token"
}

echo "listo: cluster con control nodes en $CONTROL_NODE_URL"
