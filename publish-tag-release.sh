#!/usr/bin/env bash
# Tags the current local HEAD with v<workspace version> and pushes the
# commit plus the tag, which triggers the Release workflow
# (.github/workflows/release.yml) to build and publish binaries.
set -euo pipefail

cd "$(dirname "$0")"

# Single source of truth for the version: [workspace.package] in Cargo.toml,
# read via cargo itself rather than parsed by hand.
version="$(cargo pkgid -p nook-vault | sed 's/.*[@#]//')"
tag="v${version}"

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "error: working tree has uncommitted changes; commit or stash first" >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    echo "error: tag ${tag} already exists locally" >&2
    exit 1
fi

if [ -n "$(git ls-remote --tags origin "refs/tags/${tag}")" ]; then
    echo "error: tag ${tag} already exists on origin" >&2
    exit 1
fi

echo "Tagging $(git rev-parse --short HEAD) as ${tag} and pushing to origin"
git tag -a "${tag}" -m "Release ${tag}"
git push origin HEAD
git push origin "${tag}"

echo "Done. Release workflow: https://github.com/soyrochus/nook/actions/workflows/release.yml"
