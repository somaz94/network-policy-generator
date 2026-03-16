# Changelog

All notable changes to this project will be documented in this file.

## Unreleased (2026-03-16)

### Bug Fixes

- skip major version tag deletion on first release ([962e000](https://github.com/somaz94/network-policy-generator/commit/962e000d390160238ec5b4238d4995b9c4626a23))
- add trap cleanup to Helm test ([f8093da](https://github.com/somaz94/network-policy-generator/commit/f8093daf85227850f1255991d8017fab602dd95a))
- show full undeploy output in integration test cleanup ([7eb6812](https://github.com/somaz94/network-policy-generator/commit/7eb6812745d57660fa364fb977bbeb1c47d8dd0c))
- add trap for cleanup and undeploy on test exit ([8235882](https://github.com/somaz94/network-policy-generator/commit/823588208becbe12218b693480d6bc2a353dd4db))
- force imagePullPolicy Always during integration tests ([0ebb26d](https://github.com/somaz94/network-policy-generator/commit/0ebb26dda8377df09cc5bdfdb581a51b077aff21))
- add error handling and increase timeout for controller wait in integration test ([a32b8a7](https://github.com/somaz94/network-policy-generator/commit/a32b8a792bff50683e0954e83a955bdc8ac48390))

### Code Refactoring

- replace containsString with controllerutil finalizer helpers ([b271f97](https://github.com/somaz94/network-policy-generator/commit/b271f97c437496c1b169f6ae315eec2e74bf9e40))

### Documentation

- add dist/install.yaml and e2e test documentation ([5f5c7eb](https://github.com/somaz94/network-policy-generator/commit/5f5c7eb3bea839a751ba38af72d9573d764d5de8))
- update changelog ([07ad8d5](https://github.com/somaz94/network-policy-generator/commit/07ad8d527b2a34fc6b6de0e1fc1d3c29a33b2980))

### Continuous Integration

- migrate changelog generator to go-changelog-action ([ada06c0](https://github.com/somaz94/network-policy-generator/commit/ada06c06571e4d94636b56d6d57dbc33122f7713))
- unify changelog-generator with flexible tag pattern ([ec49933](https://github.com/somaz94/network-policy-generator/commit/ec49933d0672b5cb47cfe3c1439cb034c25ae43c))

### Chores

- change license from MIT to Apache 2.0 ([0721f6e](https://github.com/somaz94/network-policy-generator/commit/0721f6e1ca0c0469942215c0756b838c721ecba5))

### Contributors

- GitHub Action
- GitHub Actions
- somaz

## [v0.1.2](https://github.com/somaz94/network-policy-generator/compare/v0.1.1...v0.1.2) (2026-03-11)

### Bug Fixes

- set GOTOOLCHAIN from go.mod to fix covdata errors ([16789e5](https://github.com/somaz94/network-policy-generator/commit/16789e577a618c223466a22de5009ea07448a91b))
- clean up failed release before helm install in test ([9aed737](https://github.com/somaz94/network-policy-generator/commit/9aed737e0a10b2b753210d739ef4c258688fc619))
- use --no-hooks for helm uninstall in test to prevent hang ([c09d602](https://github.com/somaz94/network-policy-generator/commit/c09d6024a66c075a6be0d409f9421d8bed42b30e))

### Performance Improvements

- optimize Dockerfile with build cache and smaller binary ([41c559e](https://github.com/somaz94/network-policy-generator/commit/41c559e8a4d6fb616599b41fbfed57b8219c76f9))

### Documentation

- update changelog ([880a1fc](https://github.com/somaz94/network-policy-generator/commit/880a1fc099c84498cd052be8db165549ebe4c5fb))

### Chores

- sync workflow/Makefile parity with other repos ([60f596c](https://github.com/somaz94/network-policy-generator/commit/60f596c9e33831dac579b5adc03cc72eef99ad26))
- bump version to v0.1.2 ([9d24679](https://github.com/somaz94/network-policy-generator/commit/9d2467991eee1672b61325bc9dfca9b2a9c124e6))
- upgrade Go to 1.26, use go-version-file in CI workflows ([535bd6b](https://github.com/somaz94/network-policy-generator/commit/535bd6b31634d841099e5e13e15c952cf695f13a))

### Contributors

- GitHub Action
- GitHub Actions
- somaz

## [v0.1.1](https://github.com/somaz94/network-policy-generator/compare/v0.1.0...v0.1.1) (2026-03-11)

### Bug Fixes

- add dedicated RBAC for CRD cleanup hook job ([08fadd8](https://github.com/somaz94/network-policy-generator/commit/08fadd8113957b51e8042828548eadca1eeadd42))

### Documentation

- docs/VERSION_BUMP.md ([ef7cda5](https://github.com/somaz94/network-policy-generator/commit/ef7cda51e80805438f6e13b0f63d4950dbd8d59c))
- add TROUBLESHOOTING.md and CONTRIBUTING.md, migrate golangci-lint to v2 ([e0d2538](https://github.com/somaz94/network-policy-generator/commit/e0d2538a1e82ff70f8f38dc6316a3d93d5a61a3a))
- consolidate documentation into docs/ directory ([d85f450](https://github.com/somaz94/network-policy-generator/commit/d85f450445df30caa4d8506df957e5496f06cd95))
- add version bump checklist ([1751237](https://github.com/somaz94/network-policy-generator/commit/1751237fcc2928553278e25811bb11b08dbc32b9))
- add user-facing installation guide with Helm, kubectl, and source options ([23c876c](https://github.com/somaz94/network-policy-generator/commit/23c876c7f5367e8f1c1488801c5667df2f2eb703))

### Chores

- bump version to v0.1.1 ([b93e41e](https://github.com/somaz94/network-policy-generator/commit/b93e41e188bb24a443a7bf861bb88b195b373051))

### Contributors

- GitHub Action
- somaz

## [v0.1.0](https://github.com/somaz94/network-policy-generator/compare/v0.0.1...v0.1.0) (2026-03-11)

### Features

- add helm chart test automation and update README ([3a85b1e](https://github.com/somaz94/network-policy-generator/commit/3a85b1e8893a2c88252daa275f2c38eda40db4d7))
- add helm chart and integration test automation ([362826e](https://github.com/somaz94/network-policy-generator/commit/362826eaf9f8ed1c272f6232d5fff5bc79a7bd88))
- add Cilium CNI support with PolicyEngine abstraction ([727a304](https://github.com/somaz94/network-policy-generator/commit/727a30403dcbe8e14d3a8a9ba8f7544652345004))

### Bug Fixes

- remove helm-repo before checkout to prevent untracked file conflict ([b1b93fb](https://github.com/somaz94/network-policy-generator/commit/b1b93fbe835f136e8e401d2b45cff4f603f317f5))
- resolve helm-repo checkout conflict in helm-release workflow ([1ca3bc3](https://github.com/somaz94/network-policy-generator/commit/1ca3bc35bea29f5e1fea555774bc5dcfab7d363f))
- handle first release in changelog generation ([d4514e8](https://github.com/somaz94/network-policy-generator/commit/d4514e8d69a86335843a41c980f09318f93910bb))
- skip changelog commit when no tags exist ([d0b1a08](https://github.com/somaz94/network-policy-generator/commit/d0b1a0836a4ba47953ec5e4284fabbaf9e8dcd68))
- dynamically resolve first tag in changelog generator ([2adf8e9](https://github.com/somaz94/network-policy-generator/commit/2adf8e9168aa05e90b61a6739a7785c87dcf7992))
- add DNS egress rule, remove dead code, fix validator and deprecated API usage ([935c0bc](https://github.com/somaz94/network-policy-generator/commit/935c0bcd6312624699899527b1f37ebe86dfc187))

### Code Refactoring

- extract constants and reduce code duplication in policy and controller ([7829ad2](https://github.com/somaz94/network-policy-generator/commit/7829ad2ff687a24594d1e3d84ae2d90a308480b8))

### Documentation

- update CONTRIBUTORS.md ([99273d6](https://github.com/somaz94/network-policy-generator/commit/99273d60a4b18a868cc1a706b81f8985dd4685d7))
- update changelog ([910b521](https://github.com/somaz94/network-policy-generator/commit/910b52149c510be6147da028b11743f2fa10d2a6))
- update version references and fix README badge ([7631282](https://github.com/somaz94/network-policy-generator/commit/76312821de46fceb3a6578c6c95f806aaab60dcf))
- add Cilium CNI support info to README ([cb5420e](https://github.com/somaz94/network-policy-generator/commit/cb5420eaa102cbbda5bf288486027e70a982b361))
- README.md ([bca99da](https://github.com/somaz94/network-policy-generator/commit/bca99da9275cb9eda23ba7d404aafce49fb08b06))
- README.md ([91fba1d](https://github.com/somaz94/network-policy-generator/commit/91fba1d8e7a5394a71a060d57cb5ac72e6147c73))

### Tests

- add curl connectivity tests to integration and helm test scripts ([2057ed2](https://github.com/somaz94/network-policy-generator/commit/2057ed2dc4c75f15eee7a56eced8bd56baa550d9))
- improve controller test coverage to 91.8% ([b0358aa](https://github.com/somaz94/network-policy-generator/commit/b0358aaf1a4fa17f842a531366e3ba09353ebf2d))

### Continuous Integration

- migrate release workflow to git-cliff and softprops/action-gh-release ([9d3179d](https://github.com/somaz94/network-policy-generator/commit/9d3179d108e6fdb1ee08352c3d3cee4b4f85fab0))
- add dependabot auto-merge and manifests verification ([82770f5](https://github.com/somaz94/network-policy-generator/commit/82770f599c794fc36917823bb647c9f778fa0efa))
- add release, changelog, and community workflows ([c2dc29d](https://github.com/somaz94/network-policy-generator/commit/c2dc29d7f1d49fda096c82964d9354ca01226640))

### Chores

- bump version to v0.1.0 ([3b97735](https://github.com/somaz94/network-policy-generator/commit/3b977350a7d1880bc0c1ab2dcda8a854cff1836a))
- **deps:** bump golangci/golangci-lint-action from 6 to 9 ([7db7a99](https://github.com/somaz94/network-policy-generator/commit/7db7a992208edf5922c80b142ff22f5875c4d251))
- **deps:** bump actions/setup-go from 5 to 6 ([94c3414](https://github.com/somaz94/network-policy-generator/commit/94c34146b686d7afa0ecdccab7e76ca2bf787445))
- update actions to v6 and bump version to v0.0.3 ([79756e2](https://github.com/somaz94/network-policy-generator/commit/79756e2e734a9ecd7d56ed5331763431100e410b))
- delete cover.out ([44dd84a](https://github.com/somaz94/network-policy-generator/commit/44dd84a4840dcec78a19c1ff8edf8badf6415e5a))
- ing.. create network policy ([8da086c](https://github.com/somaz94/network-policy-generator/commit/8da086c961140c2f833e234312f37a0fb6599a88))
- delete bin ([377f8e4](https://github.com/somaz94/network-policy-generator/commit/377f8e4ea5c83d4815ccf05ad667dbc50b4c7293))

### Add

- gitlab-mirror.yml ([7021f5f](https://github.com/somaz94/network-policy-generator/commit/7021f5f8b24ae7bb9f7e2a8df254932fc9f0a988))

### Contributors

- GitHub Action
- GitHub Actions
- dependabot[bot]
- somaz

## v0.0.1 (2024-12-23)

### Contributors

- somaz

