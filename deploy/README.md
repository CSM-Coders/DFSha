# Despliegue en AWS con Terraform 

Un solo comando crea el cluster completo: **3 ControlNodes** (Raft: toleran la caída de 1) y **3 DataNodes** en
instancias EC2, cada uno como contenedor Docker, con TLS/mTLS entre todos los componentes. Es el mismo sistema que
`scripts/start.sh` levanta en local, pero repartido en VMs.

```
 Cliente ──HTTPS:8000──▶ ControlNode 1 ◀──Raft:4321──▶ ControlNode 2 ◀──▶ ControlNode 3
    │                        ▲ heartbeat HTTPS (los DataNodes avisan a los 3)
    └──gRPC/TLS:6000──▶ DataNode 1 ◀─mTLS:6100─▶ DataNode 2 ◀─mTLS:6100─▶ DataNode 3
```

## Qué crea Terraform (`deploy/terraform/`)

| Recurso | Detalle |
|---|---|
| 6 instancias EC2 | `dfsha-control-1..3` y `dfsha-data-1..3` (Amazon Linux 2023, `t3.small`), repartidas entre zonas de disponibilidad de la VPC por defecto |
| 2 security groups | `sg-control` y `sg-data`, con la tabla de puertos de abajo |
| Par de claves SSH | generado por Terraform, se guarda en `deploy/terraform/dfsha-lab.pem` |
| PKI | una CA y un certificado por nodo (servidor y cliente) con la IP privada y la pública como SAN |
| Secretos | `CLUSTER_SECRET` y contraseña de `admin` aleatorios (se leen con `terraform output`) |
| Despliegue del código | sube el repo por SSH, escribe `.env` y certificados, y ejecuta `docker compose up --build -d` en cada VM |
| Verificación | espera a que haya líder Raft y estén vivos todos los DataNodes antes de terminar |

No crea roles IAM (Learner Lab no lo permite) ni Elastic IPs (el laboratorio limita la cuota y aquí harían falta 6): las IP públicas
cambian cuando el laboratorio se detiene y se reinicia, y por eso los certificados se emiten con Terraform (ver
[Ciclo de vida](#ciclo-de-vida)).

### Puertos

| Puerto | Origen | Para qué |
|---|---|---|
| 22/tcp (ambos) | `admin_cidr` (tu IP) | SSH |
| 8000/tcp (control) | `clients_cidr`, `sg-data`, `sg-control` | API REST HTTPS |
| 4321/tcp (control) | solo `sg-control` | Raft entre ControlNodes |
| 6000/tcp (data) | `clients_cidr` | gRPC público con TLS |
| 6100/tcp (data) | `sg-control` y `sg-data` | gRPC interno con mTLS |

Nada va en claro: la API y el gRPC público usan TLS, el puerto interno exige certificado de cliente y el tráfico
Raft va cifrado con el secreto del cluster.

## 1. Requisitos

- **Terraform ≥ 1.5** (`terraform version`).
- Un Learner Lab **iniciado** (círculo verde en AWS Academy) y sus credenciales temporales.
- Python 3 y `curl` en tu máquina (los usa el script que espera al cluster).
- Salida a Internet desde tu máquina hacia el puerto 22 de las VMs (el despliegue es por SSH).

## 2. Credenciales del Learner Lab

En el módulo del laboratorio abre **AWS Details → AWS CLI → Show** y exporta los tres valores en la terminal donde
vas a ejecutar Terraform (cambian cada vez que inicias el laboratorio y caducan a las ~4 h):

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
export AWS_DEFAULT_REGION=us-east-1
```

Si caducan, Terraform responde `ExpiredToken` o `InvalidClientTokenId`: inicia el laboratorio y vuelve a exportar.

## 3. Configurar y desplegar

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
curl -s https://checkip.amazonaws.com          # tu IP pública: ponla en admin_cidr como x.x.x.x/32
$EDITOR terraform.tfvars                       # region y admin_cidr

terraform init
terraform plan                                 # revisa lo que se va a crear
terraform apply                                # unos minutos (casi todo es el docker build en las VMs)
```

Al terminar, `terraform output` muestra las URLs, las IP de los DataNodes y los comandos SSH.

Variables opcionales (`variables.tf`): `clients_cidr`, `data_node_count`, `control_instance_type`,
`data_instance_type`, `data_volume_gb`, `cert_valid_days`, `admin_password`.

## 4. Usar el cluster

Desde la raíz del repo, con un entorno de Python que tenga las dependencias del cliente:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r client/requirements.txt
```

```bash
source deploy/terraform/demo.sh
```

`demo.sh` carga `CONTROL_NODE_URL` y `DFSHA_CA_CERT` (son lo mismo que imprime `terraform output -raw client_env`) y define
`dfsha`, un atajo para `python client/cli.py`. Después:

```bash
dfsha register alice alice123 && dfsha login alice alice123
```

```bash
dfsha shell
```

Usuario `admin` (comando `status`: líder, nodos, bloques y réplicas); la contraseña se lee de Terraform sin mostrarla:

```bash
login_admin && dfsha status
```

Benchmark contra AWS: medido dentro de la VPC (desde una VM de control, en un contenedor desechable) para evaluar el cluster y
no tu conexión a Internet. Los resultados del despliegue de referencia están en el informe técnico (sección 9.2).
Desde tu máquina el mismo `python scripts/benchmark.py --json resultados_aws.json` mide sobre todo tu subida a Internet. La opción
`--ha` solo sirve en local (detiene contenedores con `docker compose` en tu máquina); en AWS el failover y la re-replicación se
miden con las funciones de la sección siguiente.

## 5. Demostración de alta disponibilidad 

Con `demo.sh` cargado (sección 4) hay estas funciones, todas probadas contra el cluster de AWS:

| Función | Qué hace |
|---|---|
| `lider` | dice qué ControlNode es el líder |
| `matar_lider` | mata al líder (`docker kill`) y mide cuánto tarda el cluster en volver a escribir (necesita un login previo); `levantar_control` lo vuelve a levantar |
| `parar_datanode datanode3` / `levantar_datanode datanode3` | detiene y reinicia un DataNode; `dfsha status` muestra cómo los demás nodos recuperan las copias |
| `bloques_por_nodo` | cuántos bloques guarda cada DataNode |
| `tls_sin_ca` / `tls_con_ca` | el certificado se rechaza sin la CA del cluster y se acepta con ella |
| `bloque_cifrado` | un bloque tal como está en el disco de un DataNode (empieza con `DFS2` y el resto es AES-256-GCM) |
| `limpiar_demo` | deja vacía la cuenta de `alice` entre ensayos |

En la medición de referencia, el nuevo líder tardó 1.2 a 1.3 s en aceptar escrituras tras una caída abrupta, y con un DataNode detenido
los bloques volvieron a tener 2 copias en unos 45 s (ver el informe técnico, sección 9.2).

## Ciclo de vida

- **Cambiaste código del repo** (`control_node/`, `data_node/`, `common/`): `terraform apply` vuelve a subir y
  reconstruir solo los nodos afectados.
- **El laboratorio se detuvo y se reinició**: las instancias conservan disco y datos, pero cambian sus IP públicas.
  Con credenciales nuevas, `terraform apply` detecta el cambio, emite certificados nuevos con la **misma CA** y
  reconfigura los nodos. Los clientes siguen confiando en la misma `ca.crt`; solo cambian las URLs (`terraform
  output client_env`).
- **Credenciales caducadas** (`ExpiredToken`): vuelve a exportar las tres variables y repite el comando.
- **Terminaste**: `terraform destroy` borra todo (instancias, discos, grupos). Detener el laboratorio no borra
  nada y los discos siguen consumiendo presupuesto; las instancias en ejecución consumen unos 0.12 USD/hora en
  total (6 × `t3.small`).

## Seguridad del repositorio

El estado de Terraform (`terraform.tfstate`) contiene `CLUSTER_SECRET`, la contraseña de admin y todas las claves
privadas; `dfsha-lab.pem` es la clave SSH. Están en `.gitignore` junto con `terraform.tfvars` y `.terraform/`:
**no los subas**. Sí se versiona `.terraform.lock.hcl`. Antes del primer commit comprueba con `git add -n .`.

## Problemas frecuentes

| Síntoma | Causa y solución |
|---|---|
| `ExpiredToken` / `InvalidClientTokenId` | Credenciales del laboratorio vencidas o laboratorio detenido: inícialo y exporta las nuevas |
| `UnauthorizedOperation` al crear recursos | El Learner Lab no permite ese tipo de instancia o servicio; usa `t3.small`/`t3.medium` |
| `Timeout` / `connection refused` en `remote-exec` | `admin_cidr` no incluye tu IP actual (cambió de red) o la VM aún arranca: corrige y repite `terraform apply` |
| El cluster no queda sano en 10 min | `ssh ...` a la VM y `cd dfsha/deploy/control && sudo docker compose logs --tail 50` |
| `x509: certificate ... is valid for` | Cambió una IP pública: `terraform apply` reemite los certificados |
| Un cliente no llega a los DataNodes | `clients_cidr` demasiado restrictivo o falta el puerto 6000 en tu red |

## Alternativa manual (sin Terraform)

Los archivos `deploy/control/docker-compose.yml`, `deploy/data/docker-compose.yml`, `deploy/env.example` y
`deploy/aws/bootstrap.sh` son los mismos que usa Terraform y sirven para desplegar a mano: instala Docker con
`bootstrap.sh`, genera certificados con `python scripts/gen_certs.py --name control1 ... --san <IP>`, copia a cada VM su par
y la CA como `certs/node.crt`, `node.key` y `ca.crt`, completa un `.env` a partir de `deploy/env.example` y ejecuta
`docker compose up --build -d` en `deploy/control` (3 VMs) o `deploy/data` (3 o más).
