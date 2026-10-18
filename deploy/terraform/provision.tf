# despliegue del código: empaqueta el repo, lo sube por ssh a cada vm, escribe certificados y .env y levanta el contenedor con docker compose, si cambia el código, las ips o los certificados solo se vuelven a desplegar los nodos afectados
locals {
  repo_root = abspath("${path.module}/../..")
  src_dirs  = ["control_node", "data_node", "common", "deploy/control", "deploy/data"]
  src_files = sort([
    for f in flatten([for d in local.src_dirs : [for x in fileset("${local.repo_root}/${d}", "**") : "${d}/${x}"]]) : f
    if !strcontains(f, "__pycache__") && !endswith(f, ".pyc") && !strcontains(f, "/certs/") && !endswith(f, "/.env")
  ])
  src_hash = sha1(join("", [for f in local.src_files : filesha1("${local.repo_root}/${f}")]))

  control_private      = [for n in aws_instance.control : n.private_ip]
  control_urls_private = join(",", [for ip in local.control_private : "https://${ip}:8000"])

  ssh_key = tls_private_key.ssh.private_key_openssh
}

resource "terraform_data" "bundle" {
  triggers_replace = local.src_hash

  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = <<-EOT
      mkdir -p deploy/terraform/.build
      COPYFILE_DISABLE=1 tar --no-xattrs --exclude='__pycache__' --exclude='*.pyc' --exclude='certs' --exclude='.env' \
        -czf deploy/terraform/.build/dfsha-src.tgz control_node data_node common deploy/control deploy/data
    EOT
  }
}

resource "terraform_data" "control" {
  count = local.control_count

  triggers_replace = {
    instance = aws_instance.control[count.index].id
    src      = local.src_hash
    cert     = sha1(tls_locally_signed_cert.node["control${count.index + 1}"].cert_pem)
    peers    = join(",", local.control_private)
    secret   = sha1(local.cluster_secret)
    admin    = sha1(local.admin_password)
  }

  connection {
    type        = "ssh"
    host        = aws_instance.control[count.index].public_ip
    user        = "ec2-user"
    private_key = local.ssh_key
    timeout     = "10m"
  }

  # docker lo instala el user_data, hay que esperar a que termine
  provisioner "remote-exec" {
    inline = [
      "cloud-init status --wait >/dev/null 2>&1 || true",
      "until sudo docker compose version >/dev/null 2>&1; do sleep 5; done",
      "sudo docker buildx version 2>/dev/null | grep -qE 'buildx v?0\\.(1[7-9]|[2-9][0-9])|buildx v?[1-9]' || (sudo mkdir -p /usr/local/lib/docker/cli-plugins && sudo curl -fsSL https://github.com/docker/buildx/releases/download/v0.19.3/buildx-v0.19.3.linux-amd64 -o /usr/local/lib/docker/cli-plugins/docker-buildx && sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx)",
      "sudo docker buildx version",
      "rm -rf ~/dfsha && mkdir -p ~/dfsha",
    ]
  }

  provisioner "file" {
    source      = "${path.module}/.build/dfsha-src.tgz"
    destination = "/tmp/dfsha-src.tgz"
  }

  provisioner "file" {
    content     = tls_self_signed_cert.ca.cert_pem
    destination = "/tmp/ca.crt"
  }

  provisioner "file" {
    content     = tls_locally_signed_cert.node["control${count.index + 1}"].cert_pem
    destination = "/tmp/node.crt"
  }

  provisioner "file" {
    content     = tls_private_key.node["control${count.index + 1}"].private_key_pem_pkcs8
    destination = "/tmp/node.key"
  }

  provisioner "file" {
    content     = <<-EOT
      CLUSTER_SECRET=${local.cluster_secret}
      ADMIN_PASSWORD=${local.admin_password}
      PRIVATE_IP=${aws_instance.control[count.index].private_ip}
      RAFT_PEERS=${join(",", [for i, ip in local.control_private : "${ip}:4321" if i != count.index])}
    EOT
    destination = "/tmp/dfsha.env"
  }

  provisioner "remote-exec" {
    inline = [
      "tar -xzf /tmp/dfsha-src.tgz -C ~/dfsha",
      "mkdir -p ~/dfsha/deploy/control/certs",
      "mv /tmp/ca.crt /tmp/node.crt /tmp/node.key ~/dfsha/deploy/control/certs/",
      "chmod 600 ~/dfsha/deploy/control/certs/node.key",
      "mv /tmp/dfsha.env ~/dfsha/deploy/control/.env && chmod 600 ~/dfsha/deploy/control/.env",
      "rm -f /tmp/dfsha-src.tgz",
      "cd ~/dfsha/deploy/control && sudo docker compose up --build -d",
    ]
  }

  depends_on = [terraform_data.bundle, aws_vpc_security_group_ingress_rule.rules]
}

resource "terraform_data" "data" {
  count = var.data_node_count

  triggers_replace = {
    instance = aws_instance.data[count.index].id
    src      = local.src_hash
    cert     = sha1(tls_locally_signed_cert.node["datanode${count.index + 1}"].cert_pem)
    control  = local.control_urls_private
    secret   = sha1(local.cluster_secret)
  }

  connection {
    type        = "ssh"
    host        = aws_instance.data[count.index].public_ip
    user        = "ec2-user"
    private_key = local.ssh_key
    timeout     = "10m"
  }

  provisioner "remote-exec" {
    inline = [
      "cloud-init status --wait >/dev/null 2>&1 || true",
      "until sudo docker compose version >/dev/null 2>&1; do sleep 5; done",
      "sudo docker buildx version 2>/dev/null | grep -qE 'buildx v?0\\.(1[7-9]|[2-9][0-9])|buildx v?[1-9]' || (sudo mkdir -p /usr/local/lib/docker/cli-plugins && sudo curl -fsSL https://github.com/docker/buildx/releases/download/v0.19.3/buildx-v0.19.3.linux-amd64 -o /usr/local/lib/docker/cli-plugins/docker-buildx && sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx)",
      "sudo docker buildx version",
      "rm -rf ~/dfsha && mkdir -p ~/dfsha",
    ]
  }

  provisioner "file" {
    source      = "${path.module}/.build/dfsha-src.tgz"
    destination = "/tmp/dfsha-src.tgz"
  }

  provisioner "file" {
    content     = tls_self_signed_cert.ca.cert_pem
    destination = "/tmp/ca.crt"
  }

  provisioner "file" {
    content     = tls_locally_signed_cert.node["datanode${count.index + 1}"].cert_pem
    destination = "/tmp/node.crt"
  }

  provisioner "file" {
    content     = tls_private_key.node["datanode${count.index + 1}"].private_key_pem_pkcs8
    destination = "/tmp/node.key"
  }

  provisioner "file" {
    content     = <<-EOT
      CLUSTER_SECRET=${local.cluster_secret}
      NODE_ID=datanode${count.index + 1}
      PUBLIC_IP=${aws_instance.data[count.index].public_ip}
      PRIVATE_IP=${aws_instance.data[count.index].private_ip}
      CONTROL_NODE_URLS=${local.control_urls_private}
    EOT
    destination = "/tmp/dfsha.env"
  }

  provisioner "remote-exec" {
    inline = [
      "tar -xzf /tmp/dfsha-src.tgz -C ~/dfsha",
      "mkdir -p ~/dfsha/deploy/data/certs",
      "mv /tmp/ca.crt /tmp/node.crt /tmp/node.key ~/dfsha/deploy/data/certs/",
      "chmod 600 ~/dfsha/deploy/data/certs/node.key",
      "mv /tmp/dfsha.env ~/dfsha/deploy/data/.env && chmod 600 ~/dfsha/deploy/data/.env",
      "rm -f /tmp/dfsha-src.tgz",
      "cd ~/dfsha/deploy/data && sudo docker compose up --build -d",
    ]
  }

  depends_on = [terraform_data.bundle, terraform_data.control, aws_vpc_security_group_ingress_rule.rules]
}

# espera a que el cluster esté sano: líder raft elegido y todos los datanodes vivos
resource "terraform_data" "verify" {
  triggers_replace = {
    control = join(",", [for t in terraform_data.control : t.id])
    data    = join(",", [for t in terraform_data.data : t.id])
    certs   = join(",", [for k, c in tls_locally_signed_cert.node : sha1(c.cert_pem)])
  }

  provisioner "local-exec" {
    command = "${path.module}/wait_for_cluster.sh ${local_file.ca_crt.filename} ${var.data_node_count} ${join(" ", [for n in aws_instance.control : n.public_ip])}"
  }

  depends_on = [terraform_data.data, local_file.ca_crt]
}
