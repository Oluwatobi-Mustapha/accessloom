# Development Workflow

Identrail now provides standardized local developer workflows through:
- `Makefile`
- `Taskfile.yml`
- `.editorconfig`
- `.pre-commit-config.yaml` (optional)

## Recommended Setup

1. Install prerequisites:
   - Go (version from `go.mod`)
   - Node.js 24+ and npm
   - Optional: Terraform, Helm, pre-commit, go-task
2. Bootstrap dependencies:
   - `make bootstrap`

## Common Commands

- `make help`: list available make targets.
- `make quickstart`: bootstrap local Docker stack and run first scan.
- `make ci`: run core local CI checks (format checks, vet, Go tests, web tests, web build).
- `make fmt`: format Go and Terraform files.
- `make fmt-check`: verify formatting only.
- `make test`: run Go tests.
- `make web-test`: run frontend tests.
- `make web-build`: build frontend assets.

If you use `go-task`, equivalent commands are available via `task`.

## Optional Pre-commit Hooks

To enable optional hooks:

1. Install pre-commit (`pipx install pre-commit` or package-manager equivalent).
2. Install hooks in this repo:
   - `pre-commit install`
   - `pre-commit install --hook-type pre-push`
3. Run hooks manually on demand:
   - `make pre-commit`

Configured hooks include:
- YAML and merge-conflict checks
- trailing whitespace and EOF normalization
- Go formatting check
- Go vet on pre-push
