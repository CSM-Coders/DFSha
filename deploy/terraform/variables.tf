variable "region" {
  description = "Región de AWS (en Learner Lab: us-east-1 o us-west-2)."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Prefijo para los nombres de los recursos."
  type        = string
  default     = "dfsha"
}

variable "admin_cidr" {
  description = "CIDR desde el que se permite SSH (22) a las VMs. Debe incluir la máquina que ejecuta terraform. Ej.: \"203.0.113.7/32\" (consúltala con: curl -s https://checkip.amazonaws.com)."
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_cidr, 0))
    error_message = "admin_cidr debe ser un CIDR válido, por ejemplo 203.0.113.7/32."
  }
}

variable "clients_cidr" {
  description = "CIDR desde el que los clientes pueden llegar a la API (8000) y a los DataNodes (6000). Todo va con TLS y tokens."
  type        = string
  default     = "0.0.0.0/0"
}

variable "data_node_count" {
  description = "Número de DataNodes (mínimo 2 para RF=2; 3 recomendado)."
  type        = number
  default     = 3

  validation {
    condition     = var.data_node_count >= 2 && var.data_node_count <= 9
    error_message = "data_node_count debe estar entre 2 y 9."
  }
}

variable "control_instance_type" {
  description = "Tipo de instancia de los ControlNodes (Learner Lab permite hasta *.large)."
  type        = string
  default     = "t3.small"
}

variable "data_instance_type" {
  description = "Tipo de instancia de los DataNodes."
  type        = string
  default     = "t3.small"
}

variable "control_volume_gb" {
  description = "Disco de cada ControlNode (GB)."
  type        = number
  default     = 20
}

variable "data_volume_gb" {
  description = "Disco de cada DataNode (GB): ahí se guardan los bloques."
  type        = number
  default     = 30
}

variable "admin_password" {
  description = "Contraseña del usuario admin de DFSha. Si es null se genera una aleatoria (terraform output -raw admin_password)."
  type        = string
  default     = null
  sensitive   = true
}

variable "cert_valid_days" {
  description = "Vigencia de la CA y de los certificados de los nodos."
  type        = number
  default     = 90
}
