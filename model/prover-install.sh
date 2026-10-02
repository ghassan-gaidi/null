#!/usr/bin/env bash
# Pinned Tamarin prover installer for Null formal verification.
#
# Recreates the exact prover environment CI uses (`.github/workflows/
# tamarin.yml`): Maude 3.5.1 + tamarin-prover 1.12.0, both sha256-pinned
# so a substituted download fails loudly instead of silently proving the
# wrong thing. Outputs an environment snippet to eval.
#
# Usage:
#   ./model/prover-install.sh [dest]      # dest defaults to ./prover-env
#   source ./prover-env/env.sh            # adds maude to PATH, sets MAUDE_LIB
#
# Verify afterwards:
#   cargo run --locked -p xtask -- prover --check
set -euo pipefail

DEST="${1:-prover-env}"
# Absolute destinations are honored as-is; relative ones resolve
# against the repo root (an absolute arg used to install INSIDE the
# repo under tmp/ — fixed after it bit a real run).
case "$DEST" in
  /*) ;;
  *) DEST="$(cd "$(dirname "$0")/.." && pwd)/$DEST" ;;
esac

MAUDE_URL="https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip"
MAUDE_SHA="72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c"
TAMARIN_URL="https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz"
TAMARIN_SHA="201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6"

fail() { echo "prover-install: $*" >&2; exit 1; }

mkdir -p "$DEST"
cd "$DEST"

if [ ! -x maude-dist/maude ]; then
  echo "==> downloading Maude 3.5.1 (sha256-pinned)"
  curl -sSL -o maude.zip "$MAUDE_URL"
  echo "$MAUDE_SHA  maude.zip" | sha256sum -c - || fail "Maude checksum mismatch"
  unzip -o -q maude.zip -d maude-dist
  rm -f maude.zip
fi

if [ ! -x tamarin-prover ]; then
  echo "==> downloading tamarin-prover 1.12.0 (sha256-pinned)"
  curl -sSL -o tamarin.tar.gz "$TAMARIN_URL"
  echo "$TAMARIN_SHA  tamarin.tar.gz" | sha256sum -c - || fail "tamarin-prover checksum mismatch"
  tar -xzf tamarin.tar.gz
  rm -f tamarin.tar.gz
fi

# Persist the pins for `cargo xtask prover --check`: hash the EXTRACTED
# artifacts (every file under maude-dist + the tamarin binary), not the
# download archives — the archives are deleted above, and their hashes
# say nothing about what actually runs. (An earlier revision pinned the
# archive hashes against binary paths, so --check could never pass.)
find maude-dist tamarin-prover -type f | LC_ALL=C sort | xargs sha256sum > pins.sha256

cat > env.sh <<EOF
export PATH="$DEST/maude-dist:\$PATH"
export MAUDE_LIB="$DEST/maude-dist"
EOF

export PATH="$DEST/maude-dist:$PATH"
export MAUDE_LIB="$DEST/maude-dist"
"$DEST/maude-dist/maude" --version >/dev/null 2>&1 || fail "maude does not run"
"$DEST/tamarin-prover" --version >/dev/null 2>&1 || fail "tamarin-prover does not run"

echo "prover env ready at: $DEST"
echo "export PATH=$DEST/maude-dist:\$PATH"
echo "export MAUDE_LIB=$DEST/maude-dist"