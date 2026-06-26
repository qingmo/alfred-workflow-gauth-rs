#!/usr/bin/env bash
#
# Build the GAuth.alfredworkflow bundle.
#
# Compiles the release binary, assembles it with the Script Filter info.plist and
# icons from alfred/, and zips the result into an importable .alfredworkflow file.
#
# The bundled binary is architecture-specific (built for this machine). To use the
# workflow on a different Mac, rebuild there.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/alfred"
OUT="$ROOT/GAuth.alfredworkflow"
BIN="$ROOT/target/release/gauth"

echo "==> Building release binary"
cargo build --release --manifest-path "$ROOT/Cargo.toml"

echo "==> Validating info.plist"
plutil -lint "$SRC/info.plist" >/dev/null

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> Staging bundle contents"
cp "$SRC/info.plist" "$STAGE/"
cp "$SRC/icon.png" "$SRC/warning.png" "$SRC/time.png" "$SRC/error.png" "$STAGE/"
cp "$BIN" "$STAGE/gauth"
chmod +x "$STAGE/gauth"

# Stamp the crate version into the bundled plist so the workflow version always
# matches the binary it ships (keeps Cargo.toml as the single source of truth).
VERSION="$("$BIN" --version 2>/dev/null | awk '{print $NF}')"
if [ -n "$VERSION" ]; then
	echo "==> Stamping workflow version $VERSION"
	plutil -replace version -string "$VERSION" "$STAGE/info.plist"
fi

echo "==> Zipping $OUT"
rm -f "$OUT"
# Zip the staged contents at the archive root (Alfred expects info.plist at top level).
( cd "$STAGE" && zip -r -X "$OUT" . -x '.*' >/dev/null )

echo "==> Done: $OUT"
unzip -l "$OUT"
