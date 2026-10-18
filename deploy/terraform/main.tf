# red: usamos la vpc por defecto (el learner lab ya la trae), una subred por zona y repartimos los nodos entre ellas
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  subnet_ids    = sort(data.aws_subnets.default.ids)
  control_count = 3 # raft de 3 nodos, aguanta la caída de 1
}

# claves: par ssh que genera terraform (se guarda en dfsha-lab.pem) y secretos del cluster
resource "tls_private_key" "ssh" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "dfsha" {
  key_name_prefix = "${var.project}-"
  public_key      = tls_private_key.ssh.public_key_openssh
}

resource "local_sensitive_file" "ssh_key" {
  content         = tls_private_key.ssh.private_key_openssh
  filename        = "${path.module}/dfsha-lab.pem"
  file_permission = "0600"
}

resource "random_id" "cluster_secret" {
  byte_length = 32
}

resource "random_password" "admin" {
  length  = 20
  special = false
}

locals {
  cluster_secret = random_id.cluster_secret.hex
  admin_password = coalesce(var.admin_password, random_password.admin.result)
}

# security groups (la tabla de puertos está en deploy/README.md)
resource "aws_security_group" "control" {
  name_prefix = "${var.project}-control-"
  description = "DFSha ControlNodes"
  vpc_id      = data.aws_vpc.default.id
  tags        = { Name = "${var.project}-sg-control" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "data" {
  name_prefix = "${var.project}-data-"
  description = "DFSha DataNodes"
  vpc_id      = data.aws_vpc.default.id
  tags        = { Name = "${var.project}-sg-data" }

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  # [grupo destino, puerto, origen (cidr o grupo), descripción]
  ingress_rules = {
    control_ssh     = { sg = aws_security_group.control.id, port = 22, cidr = var.admin_cidr, from_sg = null, desc = "SSH del administrador" }
    control_api     = { sg = aws_security_group.control.id, port = 8000, cidr = var.clients_cidr, from_sg = null, desc = "API REST HTTPS (clientes)" }
    control_api_dn  = { sg = aws_security_group.control.id, port = 8000, cidr = null, from_sg = aws_security_group.data.id, desc = "API REST HTTPS (heartbeat de DataNodes)" }
    control_api_cn  = { sg = aws_security_group.control.id, port = 8000, cidr = null, from_sg = aws_security_group.control.id, desc = "API REST HTTPS (reenvio entre ControlNodes)" }
    control_raft    = { sg = aws_security_group.control.id, port = 4321, cidr = null, from_sg = aws_security_group.control.id, desc = "Raft entre ControlNodes" }
    data_ssh        = { sg = aws_security_group.data.id, port = 22, cidr = var.admin_cidr, from_sg = null, desc = "SSH del administrador" }
    data_grpc       = { sg = aws_security_group.data.id, port = 6000, cidr = var.clients_cidr, from_sg = null, desc = "gRPC publico con TLS (clientes)" }
    data_internal_c = { sg = aws_security_group.data.id, port = 6100, cidr = null, from_sg = aws_security_group.control.id, desc = "gRPC interno mTLS (ControlNodes)" }
    data_internal_d = { sg = aws_security_group.data.id, port = 6100, cidr = null, from_sg = aws_security_group.data.id, desc = "gRPC interno mTLS (entre DataNodes)" }
  }
}

resource "aws_vpc_security_group_ingress_rule" "rules" {
  for_each = local.ingress_rules

  security_group_id            = each.value.sg
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
  cidr_ipv4                    = each.value.cidr
  referenced_security_group_id = each.value.from_sg
  description                  = each.value.desc
}

resource "aws_vpc_security_group_egress_rule" "all" {
  for_each = {
    control = aws_security_group.control.id
    data    = aws_security_group.data.id
  }

  security_group_id = each.value
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Salida libre (apt, pip, imagenes base)"
}

# instancias: el user_data solo instala docker y lo demás lo hace provision.tf
resource "aws_instance" "control" {
  count = local.control_count

  ami                         = data.aws_ami.al2023.id
  instance_type               = var.control_instance_type
  subnet_id                   = local.subnet_ids[count.index % length(local.subnet_ids)]
  vpc_security_group_ids      = [aws_security_group.control.id]
  key_name                    = aws_key_pair.dfsha.key_name
  associate_public_ip_address = true
  user_data                   = file("${path.module}/../aws/bootstrap.sh")

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.control_volume_gb
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project}-control-${count.index + 1}"
    Role = "control"
  }
}

resource "aws_instance" "data" {
  count = var.data_node_count

  ami                         = data.aws_ami.al2023.id
  instance_type               = var.data_instance_type
  subnet_id                   = local.subnet_ids[(count.index + 1) % length(local.subnet_ids)]
  vpc_security_group_ids      = [aws_security_group.data.id]
  key_name                    = aws_key_pair.dfsha.key_name
  associate_public_ip_address = true
  user_data                   = file("${path.module}/../aws/bootstrap.sh")

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.data_volume_gb
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project}-data-${count.index + 1}"
    Role = "data"
  }
}
