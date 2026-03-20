variable "namespace" {
  description = "Kubernetes namespace for Identrail."
  type        = string
  default     = "identrail"
}

variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "identrail"
}

variable "chart_path" {
  description = "Path to the Identrail Helm chart."
  type        = string
  default     = "../helm/identrail"
}

variable "create_namespace" {
  description = "Create the namespace if it does not already exist."
  type        = bool
  default     = true
}

variable "create_kubernetes_secret" {
  description = "Create a Kubernetes secret from secret_data."
  type        = bool
  default     = true
}

variable "secret_name" {
  description = "Existing secret name to use when create_kubernetes_secret=false."
  type        = string
  default     = ""
}

variable "secret_data" {
  description = "Sensitive runtime values injected as Kubernetes secret string_data."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "chart_values" {
  description = "Additional Helm values merged into release settings."
  type        = map(any)
  default     = {}
}
