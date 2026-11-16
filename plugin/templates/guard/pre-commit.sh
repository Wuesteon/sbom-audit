#!/bin/sh
# sbom-audit-guard v1
# Blocks a commit that stages a class A or B secret (sbom-audit). Installed by
# `sbom-audit setup --install-guard`, removed by `sbom-audit setup --uninstall-guard`.
# A hook that was here before is kept as pre-commit.local and runs after the guard.
if command -v python3 >/dev/null 2>&1 && [ -f "@GUARD@" ]; then
  python3 "@GUARD@" || exit 1
else
  echo "sbom-audit guard: python3 or @GUARD@ missing; commit allowed (not checked)"
fi
LOCAL="$(dirname "$0")/pre-commit.local"
if [ -x "$LOCAL" ]; then
  exec "$LOCAL" "$@"
fi
exit 0
