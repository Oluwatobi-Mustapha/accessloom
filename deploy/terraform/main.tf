locals {
  resolved_chart_path = abspath(var.chart_path)
}

module "identrail" {
  source = "./modules/identrail-helm"

  namespace                = var.namespace
  release_name             = var.release_name
  chart_path               = local.resolved_chart_path
  create_namespace         = var.create_namespace
  create_kubernetes_secret = var.create_kubernetes_secret
  secret_name              = var.secret_name
  secret_data              = var.secret_data
  chart_values             = var.chart_values
}
