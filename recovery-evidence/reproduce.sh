#!/bin/sh
# Rebuild the LaminaDB recovery evidence package from scratch.
# Usage: sh reproduce.sh
# Env:   GO_BIN=/path/to/go   (default: $HOME/.lamina-toolchain/go-sdk/bin/go, then PATH)
#        EVIDENCE_OUT=path    (default: <this dir>/evidence)
#        KEEP_WORK=1          (keep the scratch data dirs for inspection)
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO=$(dirname "$HERE")

if [ "${GO_BIN:-}" = "" ]; then
  if [ -x "$HOME/.lamina-toolchain/go-sdk/bin/go" ]; then
    GO_BIN="$HOME/.lamina-toolchain/go-sdk/bin/go"
  else
    GO_BIN=$(command -v go || true)
  fi
fi
[ "${GO_BIN:-}" = "" ] && { echo "no Go toolchain found; set GO_BIN (see README section 9)" >&2; exit 1; }

export GOPATH="${GOPATH:-$HOME/.lamina-toolchain/gopath}"
export GOCACHE="${GOCACHE:-$HOME/.lamina-toolchain/gocache}"
export GOMODCACHE="${GOMODCACHE:-$HOME/.lamina-toolchain/gomod}"

echo "== build (stock kernel, no modifications) =="
(cd "$REPO" && "$GO_BIN" build -o bin/laminad ./cmd/laminad && "$GO_BIN" vet ./...)

WORK=$(mktemp -d /tmp/lamina-evidence-XXXXXX)
OUT="${EVIDENCE_OUT:-$HERE/evidence}"
echo "== drive recovery scenarios (work dir: $WORK) =="
if python3 -I "$HERE/tools/drive_recovery.py" --binary "$REPO/bin/laminad" --out "$OUT" --work "$WORK"; then
  [ "${KEEP_WORK:-0}" = "1" ] || rm -rf "$WORK"
  echo "== evidence package regenerated at $OUT =="
else
  rc=$?
  echo "driver reported unverified claims (rc=$rc); scratch kept at $WORK" >&2
  exit "$rc"
fi
