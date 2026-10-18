# pki de dfsha (equivale a scripts/gen_certs.py): una ca propia y un certificado por nodo que sirve de servidor y de cliente (mtls), con la ip privada (tráfico entre nodos) y la pública (clientes) como san; si las ips públicas cambian (el laboratorio se detuvo y se reinició) el siguiente terraform apply emite certificados nuevos con la misma ca
resource "tls_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem       = tls_private_key.ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = var.cert_valid_days * 24
  allowed_uses          = ["cert_signing", "crl_signing", "digital_signature"]

  subject {
    common_name  = "DFSha CA"
    organization = "DFSha"
  }
}

locals {
  nodes = merge(
    { for i, n in aws_instance.control : "control${i + 1}" => n },
    { for i, n in aws_instance.data : "datanode${i + 1}" => n },
  )
}

resource "tls_private_key" "node" {
  for_each    = local.nodes
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "node" {
  for_each        = local.nodes
  private_key_pem = tls_private_key.node[each.key].private_key_pem

  subject {
    common_name  = each.key
    organization = "DFSha"
  }

  dns_names    = [each.key, "localhost"]
  ip_addresses = ["127.0.0.1", each.value.private_ip, each.value.public_ip]
}

resource "tls_locally_signed_cert" "node" {
  for_each              = local.nodes
  cert_request_pem      = tls_cert_request.node[each.key].cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = var.cert_valid_days * 24
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth", "client_auth"]
}

# la ca pública se guarda local para el cliente (DFSHA_CA_CERT), ca.key no sale de terraform
resource "local_file" "ca_crt" {
  content         = tls_self_signed_cert.ca.cert_pem
  filename        = "${path.module}/certs/ca.crt"
  file_permission = "0644"
}
