
### Bug Fixes
- use --no-hooks for helm uninstall in test to prevent hang by @somaz94
- clean up failed release before helm install in test by @somaz94
- set GOTOOLCHAIN from go.mod to fix covdata errors by @somaz94

### Chore
- upgrade Go to 1.26, use go-version-file in CI workflows by @somaz94
- bump version to v0.1.2 by @somaz94
- sync workflow/Makefile parity with other repos by @somaz94

### Documentation
- update changelog by @actions-user

### Performance
- optimize Dockerfile with build cache and smaller binary by @somaz94

**Full Changelog**: https://github.com/somaz94/network-policy-generator/compare/v0.1.1...v0.1.2
