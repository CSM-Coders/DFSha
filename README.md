# DFSha — Sistema de archivos distribuido

DFS **basado en bloques** (estilo HDFS) con alta disponibilidad, replicación, acceso aleatorio tipo archivo y seguridad de extremo a
extremo. Arquitectura **Opción 1 (Cliente/Servidor con servicio compuesto y distribuido)**.

- **3 ControlNodes** (metadatos, permisos, planificación) replicados con **Raft**: recuperación automática tras la caída de uno y la elección de un nuevo líder.
- **N DataNodes** (bloques cifrados, replicados ×2) accedidos directamente por los clientes, en paralelo.
- **Cliente**: CLI, shell interactivo con `cd` (rutas y transparencia de ubicación) y librería Python con interfaz de archivo.
- Todo cifrado (TLS/mTLS, AES-256-GCM en disco) y con control de acceso (ACL por usuario/grupo, 2FA, API keys).

Documentación técnica (arquitectura, diagramas, protocolos, APIs, algoritmos, resultados medidos y validación): **informe técnico** entregado junto con este repositorio.
Despliegue en AWS (AWS Academy) con Terraform: **[deploy/README.md](deploy/README.md)**.

Repositorio: [CSM-Coders/DFSha](https://github.com/CSM-Coders/DFSha). Video de la sustentación: https://youtu.be/8o45zRgjsxg .

## Ejecución (local, Docker)

```bash
scripts/start.sh                # crea .env con secreto aleatorio y PKI local; levanta 3 ControlNodes + 3 DataNodes
curl --cacert certs/ca.crt https://localhost:8001/health
```

El repositorio no incluye claves privadas ni `.env`: el arranque los genera localmente y conserva una configuración existente.
Si prefieres preparar el entorno sin Bash (Python 3.11 o 3.12 y Docker Desktop):

```bash
python -m pip install cryptography==50.0.2
python scripts/prepare_local.py
python scripts/gen_certs.py
docker compose up --build -d
```

Si ya tienes datos, conserva tu `.env` y tus certificados anteriores. No reemplaces el secreto o `DATA_KEY`:
perderías acceso a los bloques cifrados. Un `.env` copiado de ejemplo requiere sustituir el valor de ejemplo antes de arrancar.

- ControlNodes: `https://localhost:8001`, `:8002`, `:8003` (cualquiera sirve: los seguidores reenvían al líder).
- DataNodes: `localhost:6001`–`:6003` (gRPC con TLS; el puerto interno con mTLS no se publica).
- Cuarto DataNode opcional (probar ampliación y rebalanceo): `docker compose --profile extra up -d datanode4`.
- Para el usuario `admin` (comando `status`) define `ADMIN_PASSWORD` en `.env`.
- Para cambiar claves en un clúster con datos, primero recupera/exporta los archivos y planifica su migración; no borres los volúmenes para resolver un problema de configuración.

## Usar el cliente

```bash
cd client && pip install -r requirements.txt            # los certificados se toman de ../certs/ca.crt (o DFSHA_CA_CERT)

python cli.py register alice alice123                    # crea el usuario y su home /alice
python cli.py login alice alice123
python cli.py shell                                      # consola con cd, rutas relativas y autocompletado
```

Contra un cluster desplegado en AWS (ver `deploy/README.md`) solo cambian dos variables: `CONTROL_NODE_URL` (las URLs de los ControlNodes, separadas por coma) y `DFSHA_CA_CERT` (la `ca.crt` del cluster); `terraform output -raw client_env` las imprime.

| Qué | Comandos |
|---|---|
| Árbol de archivos (RF1) | `ls [path]` · `mkdir [-p]` · `rmdir` · `rm [-r]` · `mv` · `cp [-r]` · `tree` · `stat` |
| Transferencia (RF2) | `put [-r] <local> <remoto>` · `get [-r] <remoto> <local>` |
| Acceso tipo archivo (RF3) | `cat` · `read <path> <offset> <largo>` · `write <path> <offset> <texto\|->` · `append` · `truncate` · `lock <path> shared\|exclusive [seg]` |
| Compartir | `share <path> user:NOMBRE\|group:NOMBRE r\|rw\|none` · `acl <path>` · `shared` · `group create\|ls\|add\|remove\|delete` |
| Cuenta y seguridad | `login <user> <pass> [código 2FA]` · `apikey-login` · `passwd` · `logout-all` · `2fa setup\|enable\|disable` · `apikey create\|list\|revoke` |
| Operación (admin) | `status`: líder Raft, nodos, bloques, sub-replicados |

Desde Python, con interfaz de archivo:

```python
from dfsha_client import DFShaClient
c = DFShaClient(); c.login("alice", "alice123")
with c.open("/alice/datos.bin", "r+", lock="exclusive") as f:     # modos r, r+, w, w+, a, a+
    f.seek(1_000_000); f.write(b"parche")                          # solo se reescriben los bloques tocados
    f.seek(0); cabecera = f.read(128)
# al salir del with se publica atómicamente (si hubo una excepción, los cambios se descartan)
c.share("/alice/datos.bin", "user:bob", "r")                       # compartir con bob (solo lectura)
```

## Qué hace (resumen del diseño)

- **Particionamiento**: bloques de 4 MiB repartidos entre todos los nodos, cada uno en 2 nodos distintos; los nodos con carga parecida se tratan como
  iguales para repartir cada archivo entre todos. Detalle: informe técnico, sección 6.
- **Consistencia**: metadatos fuertemente consistentes (Raft); bloques inmutables + commit atómico (copy-on-write); versiones y control optimista;
  locks compartido/exclusivo con lease; checksums verificados extremo a extremo.
- **Transferencias largas y simultáneas**: `put` renueva su upload y tokens; `get` retiene un snapshot hasta terminar, incluso si el archivo se reemplaza o elimina.
- **Alta disponibilidad**: Raft de 3 nodos con barrera de líder, seguidores que reenvían, tokens de sesión sin estado, cliente con failover;
  DataNodes con heartbeat a los tres.
- **Tolerancia a fallos de datos**: re-replicación automática, recorte de réplicas sobrantes, poda de nodos muertos, **auto-curación de bloques
  corruptos** (cuarentena + reposición), scrub periódico, GC de huérfanos y rebalanceo al añadir nodos.
- **Inventario de réplicas**: un desafío del ControlNode solicita un inventario completo posterior; detecta bloques ausentes incluso en un DataNode vivo sin confundir escrituras recientes con pérdidas.
- **Seguridad**: TLS en REST y gRPC, mTLS en el canal interno, Raft cifrado, bloques cifrados con AES-256-GCM, tokens de acceso a bloques
  firmados, autenticación de DataNodes, ACL con herencia por usuario y grupo, 2FA, API keys, bloqueo por intentos fallidos y revocación de sesiones.

## Pruebas

```bash
scripts/start.sh
pip install -r tests/requirements.txt
pytest tests -m "not integration"       # unitarias (no necesitan el cluster)
python tests/run_native_smoke.py         # 3 ControlNodes + 3 DataNodes locales con TLS; no necesita Docker
pytest tests -m "not slow"              # + integración rápida (~1 min)
pytest tests                            # TODO, incluye caídas de nodos/líder y rebalanceo (~9 min)
python scripts/benchmark.py [--quick] [--ha]    # rendimiento: latencias, MiB/s, escalado, failover (tablas en Markdown)
```

Cobertura: planificador y rebalanceador, hashing y paths; máquina de estados de metadatos (determinismo, snapshot, rename, locks);
transferencia y acceso aleatorio (fuzz contra un modelo en memoria); aislamiento y permisos (ACL, grupos, herencia, revocación de
sesiones abiertas); **seguridad** (TLS, tokens de bloque, autenticación de nodos, cifrado en reposo, sesiones, API keys, 2FA, bloqueo por
intentos); **alta disponibilidad** (matar al líder con sesiones abiertas, pérdida y recuperación de quórum, reinicio total desde el journal,
nodo sin disco, intercambio de IPs de contenedores); **réplicas** (corrupción, scrubber, caída de DataNodes, re-replicación, rebalanceo);
cliente (árbol de archivos, shell).

La prueba nativa crea exclusivamente sus propios procesos y datos en `.native-test/`, prueba fallos controlados y
cierra esos procesos al terminar. Necesita libres los puertos API 18000 en 127.0.0.11–13, Raft 14321–14323 y gRPC
16001–16003/16101–16103. No debe apuntarse su directorio de pruebas a datos de un clúster existente. Usa las direcciones 127.0.0.11–13, que macOS no tiene: se validó en Windows y no arranca en macOS.

## Estructura

```
control_node/   ControlNode: app.py (API + monitor), cluster.py (Raft), storage.py (máquina de estados), access.py y auth_routes.py (seguridad)
data_node/      DataNode: gRPC (puerto público TLS + interno mTLS), cifrado en reposo, scrub, heartbeat
client/         dfsha_client.py (librería), cli.py, shell.py
common/         dfsha_security.py (tokens y claves, compartido por ControlNode y DataNode)
proto/          dfsha.proto  (scripts/gen_proto.sh regenera y copia el código gRPC)
scripts/        start.sh, prepare_local.py (configuración), gen_certs.py (PKI), gen_proto.sh, benchmark.py
deploy/         despliegue en AWS con Terraform (deploy/terraform) y archivos para despliegue manual
tests/          unitarias, integración, alta disponibilidad, seguridad
```

## Limitaciones conocidas

- La unidad mínima de actualización es el bloque (cambiar 4 KiB reescribe un bloque de 4 MiB; ver `benchmark.py`). No hay archivos *sparse*.
- El registro de DataNodes y los leases de sesiones viven en memoria del líder (se reconstruyen en segundos por heartbeat).
- `MIN_REPLICAS=1` permite confirmar una escritura degradada con una sola copia; hasta la reparación esa copia no tiene redundancia. Usa `MIN_REPLICAS=2` en todos los ControlNodes si necesitas exigirla al confirmar.
- Compose exige `CLUSTER_SECRET`; el arranque genera uno aleatorio. Para ejecución nativa, configura explícitamente el secreto y TLS.
- El despliegue en AWS Academy está automatizado con Terraform (`deploy/terraform`); las IP públicas cambian si el laboratorio se detiene y se reinicia, y el SSH de administración queda limitado a una sola IP (`admin_cidr`). El informe técnico se entrega aparte.
