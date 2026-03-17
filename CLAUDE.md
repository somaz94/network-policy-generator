# CLAUDE.md

<br/>

## Commit Guidelines

- Do not include `Co-Authored-By` lines in commit messages.

<br/>

## Project Structure

- Kubernetes operator built with controller-runtime (kubebuilder)
- CRD: `NetworkPolicyGenerator` (apiGroup: `security.policy.io/v1`)
- Supported policy engines: `kubernetes`, `cilium`, `calico`
- Policy templates: `zero-trust`, `web-app`, `backend-api`, `database`, `monitoring`

<br/>

## Build & Test

```bash
make test                # Unit tests
make test-integration    # Integration tests (uses make deploy, local source)
make test-helm           # Helm chart tests (uses local chart path)
make manifests generate  # Regenerate CRD and RBAC manifests (commit if changed)
make bump-version VERSION=vX.Y.Z  # Bump version across all files
```

CNI engine option for integration/helm tests:

```bash
ENGINE=auto          # Auto-detect installed CNI (default)
ENGINE=kubernetes    # Kubernetes NetworkPolicy only
ENGINE=cilium        # Cilium only
ENGINE=calico        # Calico only
ENGINE=all           # Force all engines
```

<br/>

## Key Directories

- `internal/policy/` — Policy engine implementations (kubernetes, cilium, calico, templates)
- `internal/controller/` — Reconciler logic
- `config/samples/` — Sample CR YAML files
- `helm/network-policy-generator/` — Helm chart
- `hack/` — Test and utility scripts
- `docs/` — Documentation (HELM.md, TESTING.md, TROUBLESHOOTING.md, VERSION_BUMP.md)

<br/>

## Code Style

- Linter: `staticcheck` — prefer `switch` over `if-else if` chains (QF1003).
- Run `make lint` or `staticcheck ./...` to check before committing.

<br/>

## Common Pitfalls

- **podSelector location**: Correct path is `spec.policy.podSelector`, NOT `spec.podSelector`.
- **Helm CRD sync**: When adding/changing CRD fields, always copy from `config/crd/bases/` to `helm/network-policy-generator/crds/`.
- **RBAC scope**: Event (`events`) create permission must be in ClusterRole. A namespace-scoped Role cannot create events in other namespaces.
- **Dockerfile ARG scope**: In multi-stage builds, ARG must be re-declared after each `FROM`.
- **Version bump**: `make bump-version` auto-updates all files (Makefile, Chart.yaml, values.yaml, README, docs, dist/install.yaml). No manual edits needed.

<br/>

## Release Workflow

1. `make bump-version VERSION=vX.Y.Z`
2. Commit & push
3. `make docker-buildx` (build & push image)
4. `git tag vX.Y.Z && git push origin vX.Y.Z`
5. Tag push auto-triggers: `release.yml`, `helm-release.yml`, `changelog-generator.yml`

<br/>

## Language

- Communicate with the user in Korean.
