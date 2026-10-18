output "control_urls" {
  description = "URLs de los ControlNodes (cualquiera sirve: los seguidores reenvian al lider)."
  value       = [for n in aws_instance.control : "https://${n.public_ip}:8000"]
}

output "data_nodes" {
  description = "IP publica de cada DataNode (gRPC con TLS en el puerto 6000)."
  value       = { for i, n in aws_instance.data : "datanode${i + 1}" => "${n.public_ip}:6000" }
}

output "ssh" {
  description = "Comandos SSH (la clave se guarda en deploy/terraform/dfsha-lab.pem)."
  value = merge(
    { for i, n in aws_instance.control : "control${i + 1}" => "ssh -i ${abspath(local_sensitive_file.ssh_key.filename)} ec2-user@${n.public_ip}" },
    { for i, n in aws_instance.data : "datanode${i + 1}" => "ssh -i ${abspath(local_sensitive_file.ssh_key.filename)} ec2-user@${n.public_ip}" },
  )
}

output "ca_cert" {
  description = "CA del cluster para los clientes (DFSHA_CA_CERT)."
  value       = abspath(local_file.ca_crt.filename)
}

output "client_env" {
  description = "Variables para usar el cliente contra este cluster (pegalas en tu terminal)."
  value       = <<-EOT
    export CONTROL_NODE_URL=${join(",", [for n in aws_instance.control : "https://${n.public_ip}:8000"])}
    export DFSHA_CA_CERT=${abspath(local_file.ca_crt.filename)}
  EOT
}

output "admin_password" {
  description = "Contrasena del usuario admin de DFSha (terraform output -raw admin_password)."
  value       = local.admin_password
  sensitive   = true
}

output "cluster_secret" {
  description = "CLUSTER_SECRET compartido por todos los nodos (terraform output -raw cluster_secret)."
  value       = local.cluster_secret
  sensitive   = true
}
