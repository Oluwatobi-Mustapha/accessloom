# Read-Only Integration Policies

These templates define minimum read-only permissions for Identrail collectors.

## AWS IAM

- File: `deploy/policies/aws/identrail-readonly-iam-policy.json`
- Scope: IAM role and policy metadata required for AWS identity discovery.
- Usage:
  - Create policy from file.
  - Attach to a dedicated scanner role or user.
  - Run Identrail with `IDENTRAIL_AWS_SOURCE=sdk`.

## Kubernetes RBAC

- File: `deploy/policies/kubernetes/identrail-readonly-clusterrole.yaml`
- Scope: read-only access to service accounts, pods, roles, and role bindings.
- Usage:
  - Apply file to the target cluster.
  - Bind the cluster role to the service account/user used by Identrail.
  - Run Identrail with `IDENTRAIL_K8S_SOURCE=kubectl`.

## Rotation Note

- Rotate access keys and service-account credentials on a fixed cadence.
- Keep at least two active API keys during rotation so clients can switch without downtime.
