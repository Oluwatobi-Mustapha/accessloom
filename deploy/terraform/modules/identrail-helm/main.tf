locals {
  effective_secret_name = length(trimspace(var.secret_name)) > 0 ? trimspace(var.secret_name) : "${var.release_name}-secrets"
  helm_values = merge(
    var.chart_values,
    {
      secret = {
        create         = false
        existingSecret = local.effective_secret_name
      }
    }
  )
}

resource "kubernetes_namespace_v1" "identrail" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace
  }
}

resource "kubernetes_secret_v1" "identrail" {
  count = var.create_kubernetes_secret ? 1 : 0

  metadata {
    name      = local.effective_secret_name
    namespace = var.namespace
  }

  type = "Opaque"
  data = var.secret_data

  depends_on = [kubernetes_namespace_v1.identrail]
}

resource "helm_release" "identrail" {
  name             = var.release_name
  namespace        = var.namespace
  chart            = var.chart_path
  create_namespace = var.create_namespace
  wait             = var.wait
  timeout          = var.timeout

  values = [yamlencode(local.helm_values)]

  depends_on = [
    kubernetes_namespace_v1.identrail,
    kubernetes_secret_v1.identrail,
  ]
}
