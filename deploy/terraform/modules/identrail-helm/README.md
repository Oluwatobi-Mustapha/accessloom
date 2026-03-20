# identrail-helm Module

Deploys the Identrail Helm chart into an existing Kubernetes cluster.

## Inputs

- `namespace`: target namespace.
- `release_name`: helm release name.
- `chart_path`: filesystem path to chart.
- `create_namespace`: create namespace if missing.
- `create_kubernetes_secret`: create runtime secret from `secret_data`.
- `secret_name`: existing secret when not creating one.
- `secret_data`: sensitive key/value runtime configuration.
- `chart_values`: additional chart values.

## Outputs

- `namespace`
- `secret_name`
- `release_name`
- `release_status`
