# Release Pipeline

Identrail release automation is defined in:
- `.github/workflows/release.yml`

## Trigger Modes

- Tag push: `v*.*.*` (for example `v1.2.3`)
- Manual dispatch with:
  - `tag` (required)
  - `web_api_url` (optional override for web image build)

## Required Configuration

- Set repository variable `IDENTRAIL_WEB_API_URL` to the public HTTPS API base URL
  used by production web builds (for example `https://api.identrail.io`).
- For manual runs, you can override this with the `web_api_url` dispatch input.

## What the Pipeline Publishes

1. Cross-platform binaries (`cli`, `server`, `worker`) as archives.
2. SHA-256 checksum manifest (`checksums.txt`).
3. Container images to GHCR:
   - `ghcr.io/<owner>/identrail-api:<tag>`
   - `ghcr.io/<owner>/identrail-worker:<tag>`
   - `ghcr.io/<owner>/identrail-web:<tag>`
4. Auto-generated GitHub Release notes.

## Image Tag Rules

- Stable tags (`vX.Y.Z`) publish `<tag>` and `latest`.
- Pre-release tags (`vX.Y.Z-rc.1`, etc.) publish only `<tag>`.

## Recommended Usage

1. Merge all release-ready PRs into `main`.
2. Create and push a SemVer tag:
   - `git tag v1.2.3`
   - `git push origin v1.2.3`
3. Verify release assets and image digests on GitHub Releases.
