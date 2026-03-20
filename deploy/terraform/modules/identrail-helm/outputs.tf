output "namespace" {
  description = "Namespace where release is deployed."
  value       = var.namespace
}

output "secret_name" {
  description = "Runtime secret used by chart."
  value       = local.effective_secret_name
}

output "release_name" {
  description = "Helm release name."
  value       = helm_release.identrail.name
}

output "release_status" {
  description = "Helm release status."
  value       = helm_release.identrail.status
}
