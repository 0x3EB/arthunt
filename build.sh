#!/usr/bin/env bash
# Build arthunt for Windows (and Linux for local testing) as single static
# binaries with no runtime dependencies. Uses the local Go toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Remove any stray editor/tool temp files so they're never packaged or shipped.
find . -name '*.tmp.*' -type f -delete 2>/dev/null || true

# Locate Go: prefer the project-local toolchain, else PATH.
GO="${GO:-}"
if [ -z "$GO" ]; then
  if [ -x "/home/sle/dev/rt/.toolchain/go/bin/go" ]; then
    GO="/home/sle/dev/rt/.toolchain/go/bin/go"
  else
    GO="$(command -v go || true)"
  fi
fi
[ -n "$GO" ] || { echo "go toolchain not found (set \$GO)"; exit 1; }

VERSION="$("$GO" run . --version 2>/dev/null | awk '{print $2}' || echo dev)"
LDFLAGS="-s -w"
export CGO_ENABLED=0

mkdir -p dist
echo "[*] go version: $("$GO" version)"
echo "[*] running tests..."
"$GO" test ./...

echo "[*] building windows/amd64 -> dist/arthunt.exe"
GOOS=windows GOARCH=amd64 "$GO" build -trimpath -ldflags "$LDFLAGS" -o dist/arthunt.exe .

echo "[*] building windows/arm64 -> dist/arthunt-arm64.exe"
GOOS=windows GOARCH=arm64 "$GO" build -trimpath -ldflags "$LDFLAGS" -o dist/arthunt-arm64.exe .

echo "[*] building linux/amd64  -> dist/arthunt-linux"
GOOS=linux GOARCH=amd64 "$GO" build -trimpath -ldflags "$LDFLAGS" -o dist/arthunt-linux .

echo "[*] done:"
ls -la dist/
command -v sha256sum >/dev/null && (cd dist && sha256sum * > SHA256SUMS && cat SHA256SUMS)
