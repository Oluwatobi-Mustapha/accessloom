# Terraform Deployment Baseline

This Terraform baseline deploys Identrail on Kubernetes through the Helm chart.

## What It Creates

- Kubernetes namespace (optional)
- Kubernetes secret for runtime credentials (optional)
- Helm release for API/worker (and web if enabled in chart values)

## Quick Start

1. Copy example variables:
   - `cp deploy/terraform/terraform.tfvars.example deploy/terraform/terraform.tfvars`
2. Edit secrets and image tags in `terraform.tfvars`.
3. Deploy:
   - `cd deploy/terraform`
   - `terraform init`
   - `terraform plan`
   - `terraform apply`

## Required Provider Auth

- Kubernetes provider auth from kubeconfig or in-cluster identity.
- Helm provider uses the same Kubernetes context.

## Notes

- This module assumes a Kubernetes cluster already exists.
- For production, use external secret management and set `create_kubernetes_secret=false` with `secret_name`.
