#!/usr/bin/env bash
set -euo pipefail

# bump-version.sh - Automatically update version across all project files
#
# Usage:
#   ./hack/bump-version.sh <new-version>
#   ./hack/bump-version.sh --current
#   make bump-version VERSION=v0.3.0
#   make version

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Extract current version from Makefile
get_current_version() {
    grep -o 'network-policy-generator:v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' "${ROOT_DIR}/Makefile" \
        | head -1 \
        | cut -d: -f2
}

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <new-version>"
    echo "       $0 --current"
    echo "Example: $0 v0.3.0"
    exit 1
fi

# Show current version and exit
if [[ "$1" == "--current" ]]; then
    CURRENT="$(get_current_version)"
    if [[ -z "${CURRENT}" ]]; then
        echo "Error: Could not detect current version from Makefile"
        exit 1
    fi
    echo "Current version: ${CURRENT}"
    echo ""
    echo "Version in each file:"
    printf "  %-25s %s\n" "Makefile:" "${CURRENT}"
    printf "  %-25s %s\n" "Chart.yaml (version):" "$(grep '^version:' "${ROOT_DIR}/helm/network-policy-generator/Chart.yaml" | awk '{print $2}')"
    printf "  %-25s %s\n" "Chart.yaml (appVersion):" "$(grep '^appVersion:' "${ROOT_DIR}/helm/network-policy-generator/Chart.yaml" | awk -F'"' '{print $2}')"
    printf "  %-25s %s\n" "values.yaml (image.tag):" "$(grep '  tag:' "${ROOT_DIR}/helm/network-policy-generator/values.yaml" | awk '{print $2}')"
    printf "  %-25s %s\n" "kustomization (newTag):" "$(grep 'newTag:' "${ROOT_DIR}/config/manager/kustomization.yaml" | awk '{print $2}')"
    exit 0
fi

NEW_VERSION="$1"

# Validate version format (vX.Y.Z)
if [[ ! "${NEW_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format vX.Y.Z (e.g., v0.3.0)"
    exit 1
fi

# Strip 'v' prefix for chart version
CHART_VERSION="${NEW_VERSION#v}"

# Detect current version
CURRENT_VERSION="$(get_current_version)"
if [[ -z "${CURRENT_VERSION}" ]]; then
    echo "Error: Could not detect current version from Makefile"
    exit 1
fi

CURRENT_CHART_VERSION="${CURRENT_VERSION#v}"

if [[ "${CURRENT_VERSION}" == "${NEW_VERSION}" ]]; then
    echo "Already at version ${NEW_VERSION}, nothing to do."
    exit 0
fi

echo "Bumping version: ${CURRENT_VERSION} -> ${NEW_VERSION}"
echo ""

update_file() {
    local file="$1"
    local pattern="$2"
    local replacement="$3"
    local label="$4"

    if [[ ! -f "${file}" ]]; then
        echo "  [SKIP] ${label} (not found)"
        return
    fi

    if sed --version >/dev/null 2>&1; then
        sed -i "s|${pattern}|${replacement}|g" "${file}"
    else
        sed -i '' "s|${pattern}|${replacement}|g" "${file}"
    fi
    echo "  [OK]   ${label}"
}

echo "==> Updating required files..."
update_file "${ROOT_DIR}/Makefile" \
    "network-policy-generator:${CURRENT_VERSION}" \
    "network-policy-generator:${NEW_VERSION}" \
    "Makefile (IMG)"

update_file "${ROOT_DIR}/helm/network-policy-generator/Chart.yaml" \
    "^version: ${CURRENT_CHART_VERSION}" \
    "version: ${CHART_VERSION}" \
    "Chart.yaml (version)"

update_file "${ROOT_DIR}/helm/network-policy-generator/Chart.yaml" \
    "^appVersion: \"${CURRENT_VERSION}\"" \
    "appVersion: \"${NEW_VERSION}\"" \
    "Chart.yaml (appVersion)"

update_file "${ROOT_DIR}/helm/network-policy-generator/values.yaml" \
    "tag: ${CURRENT_VERSION}" \
    "tag: ${NEW_VERSION}" \
    "values.yaml (image.tag)"

update_file "${ROOT_DIR}/config/manager/kustomization.yaml" \
    "newTag: ${CURRENT_VERSION}" \
    "newTag: ${NEW_VERSION}" \
    "kustomization.yaml (newTag)"

echo ""
echo "==> Updating documentation files..."
update_file "${ROOT_DIR}/README.md" \
    "${CURRENT_VERSION}" \
    "${NEW_VERSION}" \
    "README.md"

update_file "${ROOT_DIR}/docs/HELM.md" \
    "${CURRENT_VERSION}" \
    "${NEW_VERSION}" \
    "docs/HELM.md"

update_file "${ROOT_DIR}/docs/VERSION_BUMP.md" \
    "${CURRENT_VERSION}" \
    "${NEW_VERSION}" \
    "docs/VERSION_BUMP.md"

update_file "${ROOT_DIR}/docs/VERSION_BUMP.md" \
    "${CURRENT_CHART_VERSION}" \
    "${CHART_VERSION}" \
    "docs/VERSION_BUMP.md (chart version)"

echo ""
echo "==> Regenerating dist/install.yaml..."
cd "${ROOT_DIR}"
if command -v make >/dev/null 2>&1; then
    make build-installer 2>&1 | tail -1
    echo "  [OK]   dist/install.yaml"
else
    echo "  [SKIP] make not found, run 'make build-installer' manually"
fi

echo ""
echo "Done! Version bumped to ${NEW_VERSION}"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Commit: git commit -am \"chore: bump version to ${NEW_VERSION}\""
echo "  3. Push: git push origin main"
echo "  4. Build image: make docker-buildx"
echo "  5. Tag: git tag ${NEW_VERSION} && git push origin ${NEW_VERSION}"
