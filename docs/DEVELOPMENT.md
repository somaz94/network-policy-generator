# Development

Guide for building, testing, and contributing to network-policy-generator.

<br/>

## Table of Contents

- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Build](#build)
- [Testing](#testing)
- [Docker](#docker)
- [Workflow](#workflow)
- [CI/CD Workflows](#cicd-workflows)
- [Conventions](#conventions)

<br/>

## Prerequisites

- Go 1.26+
- Make
- Docker (for container builds)
- Kind (for e2e tests)
- kubectl

<br/>

## Project Structure

```
.
├── cmd/
│   └── main.go                       # Entry point
├── api/
│   └── v1/                           # NetworkPolicyGenerator CRD types
│       ├── networkpolicygenerator_types.go
│       ├── networkpolicygenerator_webhook.go
│       └── zz_generated.deepcopy.go
├── internal/
│   ├── controller/                   # Reconciliation logic
│   │   ├── networkpolicygenerator_controller.go
│   │   ├── module_handlers.go
│   │   └── metrics.go
│   ├── policy/                       # Policy generation engines
│   │   ├── generator.go
│   │   ├── engine.go
│   │   ├── kubernetes.go             # Kubernetes native policies
│   │   ├── cilium.go                 # Cilium network policies
│   │   ├── calico.go                 # Calico network policies
│   │   ├── templates.go
│   │   ├── validator.go
│   │   └── rules.go
│   └── monitor/                      # Traffic monitoring
│       ├── monitor.go
│       └── collector.go
├── config/
│   ├── crd/                          # CRD definitions
│   ├── default/                      # Default kustomize overlay
│   ├── manager/                      # Manager deployment
│   ├── rbac/                         # RBAC manifests
│   ├── webhook/                      # Webhook configuration
│   ├── prometheus/                   # Prometheus ServiceMonitor
│   └── samples/                      # Sample CRs
├── helm/
│   └── network-policy-generator/     # Helm chart
├── hack/                             # Helper scripts
│   ├── bump-version.sh
│   ├── test-helm.sh
│   └── test-integration.sh
├── test/
│   ├── e2e/                          # End-to-end tests
│   └── utils/                        # Test utilities
├── docs/                             # Documentation
├── .github/workflows/                # CI/CD pipelines
├── Dockerfile                        # Multi-stage build (distroless)
└── Makefile                          # Build, test, deploy
```

<br/>

### Key Directories

| Directory | Description |
|-----------|-------------|
| `cmd/` | Controller manager entry point |
| `api/v1/` | NetworkPolicyGenerator CRD types + webhook |
| `internal/controller/` | Reconciliation, module handlers, metrics |
| `internal/policy/` | Policy engines (Kubernetes, Cilium, Calico), templates, validation |
| `internal/monitor/` | Traffic monitoring and collection |
| `config/` | Kustomize manifests for CRDs, RBAC, webhooks, deployment |
| `helm/` | Helm chart for production deployment |

<br/>

## Build

```bash
make build               # Build binary → bin/manager
make run                  # Run controller locally
make docker-build         # Build Docker image
make docker-buildx        # Multi-arch build (arm64, amd64, s390x, ppc64le)
```

<br/>

## Testing

```bash
make test                 # Unit tests with envtest (coverage → cover.out)
make test-e2e             # E2E tests on Kind cluster
make test-integration     # Integration tests (ENGINE=auto|kubernetes|cilium|calico|all)
make test-helm            # Helm chart tests (lint, install, sync, uninstall)
make lint                 # Run golangci-lint
```

<br/>

## Docker

```bash
make docker-build IMG=somaz940/network-policy-generator:v0.2.1
make docker-push
make docker-buildx        # Multi-platform build + push
```

- **Builder**: golang:1.26 with BuildKit cache
- **Runtime**: gcr.io/distroless/static:nonroot

<br/>

## Deployment

```bash
make manifests            # Generate CRDs, RBAC, webhooks
make generate             # Generate DeepCopy methods
make install              # Install CRDs to cluster
make deploy               # Deploy controller to cluster
make undeploy             # Remove controller from cluster
make build-installer      # Generate consolidated install.yaml
```

<br/>

## Version Management

```bash
make version                        # Show current version
make bump-version VERSION=v0.3.0    # Bump version across all files
```

<br/>

## Workflow

```bash
make check-gh                                    # Verify gh CLI is installed and authenticated
make branch name=cilium-engine                   # Create feature branch from main
make pr title="feat: add Cilium engine support"  # Test → push → create PR
```

<br/>

## CI/CD Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `test.yml` | push, PR, dispatch | Unit tests + manifest verification |
| `test-e2e.yml` | push, PR, dispatch | E2E tests on Kind cluster |
| `lint.yml` | dispatch | golangci-lint |
| `release.yml` | tag push `v*` | GitHub release with git-cliff changelog |
| `helm-release.yml` | tag push, dispatch | Package & publish Helm chart |
| `changelog-generator.yml` | after release, PR merge | Auto-generate CHANGELOG.md |
| `contributors.yml` | after changelog | Auto-generate CONTRIBUTORS.md |
| `gitlab-mirror.yml` | push to main | Mirror to GitLab |
| `stale-issues.yml` | daily cron | Auto-close stale issues |
| `dependabot-auto-merge.yml` | PR (dependabot) | Auto-merge minor/patch updates |
| `issue-greeting.yml` | issue opened | Welcome message |

<br/>

## Conventions

- **Commits**: Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`, `chore:`)
- **Framework**: Kubebuilder with controller-runtime
- **Testing**: Ginkgo/Gomega + envtest + stretchr/testify
- **CNI Engines**: Kubernetes, Cilium, Calico
- **Docker**: Multi-stage distroless, multi-arch support
- **Tools**: controller-gen, kustomize, envtest, golangci-lint
