#!/bin/zsh
# Rebuilds XcodeSupport/Burrow.icns from design/burrow-icon.svg.
# Requires librsvg (brew install librsvg).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SVG="$ROOT_DIR/design/burrow-icon.svg"
OUT="$ROOT_DIR/XcodeSupport/Burrow.icns"
ICONSET="$(mktemp -d)/Burrow.iconset"
mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
  rsvg-convert -w "$size" -h "$size" "$SVG" -o "$ICONSET/icon_${size}x${size}.png"
  rsvg-convert -w "$((size * 2))" -h "$((size * 2))" "$SVG" -o "$ICONSET/icon_${size}x${size}@2x.png"
done
iconutil --convert icns "$ICONSET" --output "$OUT"
echo "Wrote $OUT"
