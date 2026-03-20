output "namespace" {
  description = "Namespace where Identrail is deployed."
  value       = module.identrail.namespace
}

output "secret_name" {
  description = "Secret used by Helm runtime."
  value       = module.identrail.secret_name
}

output "release_name" {
  description = "Helm release name."
  value       = module.identrail.release_name
}

output "release_status" {
  description = "Helm release status."
  value       = module.identrail.release_status
}
