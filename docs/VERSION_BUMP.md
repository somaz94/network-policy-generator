# Version Bump Guide

## Quick Start

Use the automated script to bump versions across all files at once:

```bash
# Check current version
make version

# Bump to a new version
make bump-version VERSION=v0.3.0
```

This automatically updates all required files and regenerates `dist/install.yaml`.

<br/>

## What Gets Updated

The `bump-version` script updates the following files:

### Required Files

| File | Field | Example |
|------|-------|---------|
| `Makefile` | `IMG ?= somaz940/network-policy-generator:<version>` | `v0.2.1` |
| `helm/network-policy-generator/Chart.yaml` | `version` (chart version, without `v` prefix) | `0.2.1` |
| `helm/network-policy-generator/Chart.yaml` | `appVersion` (app version, with `v` prefix) | `"v0.2.1"` |
| `helm/network-policy-generator/values.yaml` | `image.tag` | `v0.2.1` |
| `config/manager/kustomization.yaml` | `newTag` | `v0.2.1` |

### Documentation Files

| File | Location | Note |
|------|----------|------|
| `README.md` | Installation examples (`--set image.tag=`, `make deploy IMG=`) | Update version in code blocks |
| `docs/HELM.md` | Configuration table (`image.tag` default) | Update default value |
| `docs/HELM.md` | Custom Values Example (`tag:`) | Update example version |
| `docs/VERSION_BUMP.md` | Example versions in tables | Update example values |

### Generated Files

| File | Method |
|------|--------|
| `dist/install.yaml` | Regenerated via `make build-installer` |

<br/>

## Script Usage

```bash
# Check current version across all files
./hack/bump-version.sh --current

# Bump version (validates vX.Y.Z format)
./hack/bump-version.sh v0.3.0
```

Or via Makefile:

```bash
make version                       # Show current version
make bump-version VERSION=v0.3.0   # Bump to v0.3.0
```

<br/>

## Release Steps

1. Bump version: `make bump-version VERSION=v0.x.x`
2. Review changes: `git diff`
3. Commit: `git commit -am "chore: bump version to v0.x.x"`
4. Push: `git push origin main`
5. Build and push Docker image: `make docker-buildx` (or `make docker-build docker-push`)
6. Create and push tag: `git tag v0.x.x && git push origin v0.x.x`
7. Workflows triggered automatically:
   - `release.yml` - Creates GitHub Release with git-cliff changelog
   - `helm-release.yml` - Packages and publishes Helm chart to gh-pages
   - `changelog-generator.yml` - Updates CHANGELOG.md
