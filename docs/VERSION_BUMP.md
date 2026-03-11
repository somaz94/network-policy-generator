# Version Bump Checklist

When releasing a new version, update the following files:

<br/>

## Required Files

| File | Field | Example |
|------|-------|---------|
| `Makefile` | `IMG ?= somaz940/network-policy-generator:<version>` | `v0.1.1` |
| `helm/network-policy-generator/Chart.yaml` | `version` (chart version, without `v` prefix) | `0.1.1` |
| `helm/network-policy-generator/Chart.yaml` | `appVersion` (app version, with `v` prefix) | `"v0.1.1"` |
| `helm/network-policy-generator/values.yaml` | `image.tag` | `v0.1.1` |
| `config/manager/kustomization.yaml` | `newTag` | `v0.1.1` |

<br/>

## Documentation Files

| File | Location | Note |
|------|----------|------|
| `README.md` | Installation examples (`--set image.tag=`, `make deploy IMG=`, `make build-installer IMG=`) | Update version in code blocks |
| `helm/README.md` | Configuration table (`image.tag` default) | Update default value |
| `helm/README.md` | Custom Values Example (`tag:`) | Update example version |

<br/>

## Release Steps

1. Update all files listed above
2. Commit: `git commit -m "chore: bump version to v0.x.x"`
3. Push: `git push origin main`
4. Build and push Docker image: `make docker-buildx` (or `make docker-build docker-push`)
5. Create and push tag: `git tag v0.x.x && git push origin v0.x.x`
6. Workflows triggered automatically:
   - `release.yml` - Creates GitHub Release with git-cliff changelog
   - `helm-release.yml` - Packages and publishes Helm chart to gh-pages
   - `changelog-generator.yml` - Updates CHANGELOG.md
