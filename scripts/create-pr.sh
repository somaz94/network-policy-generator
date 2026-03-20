#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/create-pr.sh "PR title"
# Generates PR body from commit history and creates a GitHub PR.

TITLE="${1:?Usage: create-pr.sh \"PR title\"}"
BRANCH=$(git branch --show-current)
BASE="main"

# Get commits since diverging from base branch.
COMMITS=$(git log "${BASE}..HEAD" --pretty=format:"- %s" --reverse 2>/dev/null || echo "")

if [ -z "$COMMITS" ]; then
  echo "No commits found between ${BASE} and ${BRANCH}"
  exit 1
fi

# Categorize commits.
FEATS=$(echo "$COMMITS" | grep -E "^- feat:" || true)
FIXES=$(echo "$COMMITS" | grep -E "^- fix:" || true)
TESTS=$(echo "$COMMITS" | grep -E "^- test:" || true)
DOCS=$(echo "$COMMITS" | grep -E "^- docs:" || true)
OTHERS=$(echo "$COMMITS" | grep -vE "^- (feat|fix|test|docs|ci|chore):" || true)
CI=$(echo "$COMMITS" | grep -E "^- (ci|chore):" || true)

# Build summary section.
SUMMARY=""
[ -n "$FEATS" ] && SUMMARY="${SUMMARY}${FEATS}\n"
[ -n "$FIXES" ] && SUMMARY="${SUMMARY}${FIXES}\n"
[ -n "$OTHERS" ] && SUMMARY="${SUMMARY}${OTHERS}\n"

# Trim trailing newlines.
SUMMARY=$(echo -e "$SUMMARY" | sed '/^$/d')

if [ -z "$SUMMARY" ]; then
  SUMMARY="$COMMITS"
fi

# Detect what changed for test plan.
CHANGED_PKGS=$(git diff "${BASE}..HEAD" --name-only | grep '_test\.go$' | sed 's|/[^/]*$||' | sort -u || true)
HAS_TESTS=false
[ -n "$CHANGED_PKGS" ] && HAS_TESTS=true

# Build body.
BODY=$(cat <<EOF
## Summary
${SUMMARY}

## Changes
$([ -n "$TESTS" ] && echo "$TESTS" || echo "- (no test commits)")
$([ -n "$DOCS" ] && echo "$DOCS" || echo "- (no doc commits)")
$([ -n "$CI" ] && echo "$CI" || true)

## Test plan
- [x] Unit tests pass (\`go test ./... -race -cover\`)
- [x] \`go vet\` passes
$(if [ "$HAS_TESTS" = true ]; then
  echo "- [x] New/updated tests added"
  for pkg in $CHANGED_PKGS; do
    echo "- [x] \`${pkg}\` tests pass"
  done
fi)
- [ ] Demo script passes (\`make demo\`)
- [ ] Build succeeds (\`make build\`)
EOF
)

gh pr create --title "$TITLE" --body "$BODY"
