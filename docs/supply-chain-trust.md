# Supply Chain Trust Artifacts

Supply-chain trust automation is defined in:
- `.github/workflows/supply-chain-trust.yml`

## Trigger Modes

- Automatic: when a GitHub Release is published
- Manual: workflow dispatch with a release tag

## Artifacts Produced

- Binary SBOM (`CycloneDX JSON`)
- Image SBOMs (`CycloneDX JSON`) when release images exist in GHCR
- Signed checksum manifest:
  - `checksums.txt`
  - `checksums.txt.sig`
  - `checksums.txt.pem`
- Build provenance attestations via `actions/attest-build-provenance`
- Keyless image signatures via Cosign (when images are available)

## Required Permissions and Settings

Workflow permissions:
- `contents: write`
- `id-token: write`
- `attestations: write`
- `packages: read`

Repository requirements:
- GitHub Actions enabled with write token permissions
- GHCR access for repository images
- OIDC-enabled keyless signing support (Cosign)

## Operational Notes

- If release images are not available yet, image SBOM/signing steps are skipped with logs.
- Trust artifacts are uploaded both as workflow artifacts and attached to the GitHub Release when present.
