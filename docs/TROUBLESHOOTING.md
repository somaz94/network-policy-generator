# Troubleshooting

<br/>

## Helm Test Issues

### `UPGRADE FAILED: "release-name" has no deployed releases`

A previous failed install/uninstall left a stuck release.

```bash
# Check stuck releases
helm list -a --all-namespaces | grep <release-name>

# Force cleanup
helm uninstall <release-name> --no-hooks
kubectl delete ns network-policy-generator-system --ignore-not-found
```

### CRD cleanup hook fails: `BackoffLimitExceeded`

The cleanup job's ServiceAccount lacks `apiextensions.k8s.io` CRD delete permission.

```bash
# Force uninstall without hooks
helm uninstall <release-name> --no-hooks

# Manually delete CRD if needed
kubectl delete crd networkpolicygenerators.security.policy.io --ignore-not-found

# Delete stuck job
kubectl delete job -n network-policy-generator-system -l app.kubernetes.io/name=network-policy-generator --ignore-not-found
```

### Helm uninstall hangs

The pre-delete hook job is failing repeatedly.

```bash
# Cancel and force uninstall
helm uninstall <release-name> --no-hooks

# Clean up namespace
kubectl delete ns network-policy-generator-system --ignore-not-found
```

### Untracked file blocks `git checkout gh-pages` (helm-release workflow)

The packaged `.tgz` file causes checkout conflict in the CI workflow.

This is fixed in the latest `helm-release.yml` with `rm -rf helm-repo/` before checkout.

<br/>

## Controller Issues

### Controller pod is CrashLoopBackOff

```bash
# Check logs
kubectl logs -n network-policy-generator-system deployment/network-policy-generator-controller-manager --previous

# Check events
kubectl describe pod -n network-policy-generator-system -l control-plane=controller-manager
```

Common causes:
- CRD not installed: Run `make install` or reinstall Helm chart
- RBAC permission denied: Check ClusterRole and ClusterRoleBinding
- Port conflict: Metrics (8443) or health probe (8081) port already in use

### CRD not found

```bash
# Verify CRD exists
kubectl get crd networkpolicygenerators.security.policy.io

# Reinstall CRDs
make install

# Or via Helm (CRDs are in helm/network-policy-generator/crds/)
helm upgrade <release-name> ./helm/network-policy-generator
```

### NetworkPolicy not generated after creating CR

```bash
# Check CR status
kubectl get networkpolicygenerator <name> -o yaml

# Check controller logs
kubectl logs -n network-policy-generator-system deployment/network-policy-generator-controller-manager -f

# Verify the CR is in "enforcing" mode (not "learning")
kubectl get networkpolicygenerator <name> -o jsonpath='{.spec.mode}'
```

### Finalizer stuck on deletion

```bash
# Check if controller is running
kubectl get pods -n network-policy-generator-system

# If controller is down, manually remove finalizer
kubectl patch networkpolicygenerator <name> -p '{"metadata":{"finalizers":null}}' --type=merge
```

<br/>

## CI/CD Issues

### `git push` rejected (remote ahead)

Workflow-generated commits (CHANGELOG.md, CONTRIBUTORS.md) can make remote ahead.

```bash
git pull --rebase origin main
git push origin main
```

### Release workflow: `GITHUB_TOKEN` doesn't trigger other workflows

This is expected. GITHUB_TOKEN-triggered events don't trigger other workflows (circular prevention). Use `PAT_TOKEN` for operations that need to trigger downstream workflows.

### Dependabot PR merge fails: OAuth token lacks `workflow` scope

Dependabot PRs that modify `.github/workflows/` files need the `workflow` scope. Merge these manually via GitHub web UI.

<br/>

## Build Issues

### `make manifests generate` shows diff in CI

Generated files are out of date. Run locally and commit:

```bash
make manifests generate
git add config/ api/
git commit -m "chore: update generated manifests"
```

### Docker buildx fails

```bash
# Create builder if not exists
docker buildx create --name mybuilder --use

# Verify platforms
docker buildx inspect --bootstrap
```
