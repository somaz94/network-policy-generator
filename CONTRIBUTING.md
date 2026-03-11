# Contributing

Thank you for your interest in contributing to Network Policy Generator!

<br/>

## Getting Started

### Prerequisites

- Go 1.26+
- Docker 17.03+
- kubectl v1.11.3+
- Access to a Kubernetes cluster (Kind recommended for local development)

### Setup

```bash
git clone https://github.com/somaz94/network-policy-generator.git
cd network-policy-generator

# Install all required tools (controller-gen, kustomize, envtest, golangci-lint)
make install-tools
```

<br/>

## Development Workflow

### 1. Create a branch

```bash
git checkout -b feat/your-feature
```

### 2. Make changes and verify

```bash
# Format and lint
make fmt
make vet
make lint

# Regenerate manifests and deepcopy (required if you change API types)
make manifests generate

# Run unit tests
make test

# Run integration tests (requires a running cluster)
make test-integration

# Run Helm tests
make test-helm
```

### 3. Commit with conventional commits

We use [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Usage |
|--------|-------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `ci:` | CI/CD changes |
| `chore:` | Maintenance (deps, version bumps) |
| `refactor:` | Code restructuring |
| `test:` | Test additions/changes |

```bash
git commit -m "feat: add support for egress policies"
```

### 4. Push and create a PR

```bash
git push origin feat/your-feature
```

Then create a Pull Request on GitHub.

<br/>

## Code Structure

```
api/v1/                  # CRD type definitions
internal/controller/     # Controller reconciliation logic
internal/policy/         # Policy generation (kubernetes, cilium)
config/                  # Kustomize configs, CRDs, RBAC, samples
helm/                    # Helm chart
hack/                    # Test scripts
docs/                    # Documentation
```

<br/>

## Running Tests

```bash
make test                # Unit tests
make test-e2e            # E2E tests (requires Kind cluster)
make test-integration    # Integration tests (requires running cluster)
make test-helm           # Helm chart tests
```

<br/>

## Linting

We use golangci-lint with strict settings. Run before committing:

```bash
make lint        # Check for issues
make lint-fix    # Auto-fix where possible
```

<br/>

## Questions?

Open an [issue](https://github.com/somaz94/network-policy-generator/issues) for questions or discussion.
