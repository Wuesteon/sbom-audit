#!/bin/bash
# Stage an eval case's workspace from the checked-in fixtures. `claude plugin eval --scaffold`
# runs each case's own scaffold.sh with the sandbox workspace as the working directory; those
# one-liners call this script with a mode. Only the workspace is written; nothing here touches
# a real evidence repository, a real project or the network.
#
#   evidence   ./security/ from fixtures/security (the last-scan state: lookup, incident)
#   portfolio  ./<project>/ for each fixture project, each its own git repository (setup)
#   run        portfolio + ./security/sbom-audit.toml (fetch = false, commit = false)
#   assess     evidence + portfolio, and shop-web gains a server.js that calls lodash's template with
#              request input, so "we never call template" is a claim the code disproves
#   secrets    the planted-secrets portfolio from tests/secrets_fixture.py, scanned once so
#              security/SECRETS.md exists (gitleaks required); values never leave the workspace
#   hosts      ./security/sbom-audit.toml with two made-up servers (reserved .invalid names, so a
#              connection attempt fails at name resolution and nothing is ever reachable)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export GIT_AUTHOR_NAME=eval GIT_AUTHOR_EMAIL=eval@example.invalid
export GIT_COMMITTER_NAME=eval GIT_COMMITTER_EMAIL=eval@example.invalid
export GIT_AUTHOR_DATE="2026-11-01T12:00:00Z" GIT_COMMITTER_DATE="2026-11-01T12:00:00Z"

portfolio() {
  for src in "$HERE"/projects/*/; do
    name="$(basename "$src")"
    cp -R "$src" "./$name"
    git -C "./$name" init -q -b main
    git -C "./$name" -c commit.gpgsign=false add -A
    git -C "./$name" -c commit.gpgsign=false commit -q -m "initial"
  done
}

case "${1:-}" in
  evidence)
    cp -R "$HERE/security" ./security
    ;;
  portfolio)
    portfolio
    ;;
  run)
    portfolio
    mkdir -p ./security
    cp "$HERE/security/sbom-audit.toml" ./security/sbom-audit.toml
    ;;
  assess)
    cp -R "$HERE/security" ./security
    portfolio
    cat > ./shop-web/server.js <<'JS'
const http = require("http");
const _ = require("lodash");

// renders a greeting from a template the caller sends
http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  const render = _.template(url.searchParams.get("tpl") || "hello <%= name %>",
                            { variable: url.searchParams.get("as") || "data" });
  res.end(render({ name: url.searchParams.get("name") || "world" }));
}).listen(3000);
JS
    git -C ./shop-web -c commit.gpgsign=false commit -q -am "greeting endpoint"
    ;;
  secrets)
    PYTHONPATH="$ROOT:$ROOT/scripts" python3 -c \
      'from pathlib import Path; from tests.secrets_fixture import write_fixture_portfolio; write_fixture_portfolio(Path("."))'
    python3 "$ROOT/scripts/sbom_audit_cli.py" secrets scan --out ./security >/dev/null 2>&1 || test $? -eq 1
    test -f ./security/SECRETS.md
    ;;
  hosts)
    mkdir -p ./security
    cat > ./security/sbom-audit.toml <<'TOML'
[hosts]
enabled = true

[hosts.servers."box-a"]
address = "box-a.invalid"
admin = "root@box-a.invalid"
production = false

[hosts.servers."web-1"]
address = "web-1.invalid"
admin = "deploy@web-1.invalid"
production = true
TOML
    ;;
  *)
    echo "usage: scaffold.sh evidence|portfolio|run|assess|secrets|hosts" >&2
    exit 2
    ;;
esac
