#!/bin/zsh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_NAME="Burrow"
EXECUTABLE_NAME="Burrow"
BUNDLE_ID="${BURROW_BUNDLE_ID:-com.jianzhou.burrow}"
APP_DIR="${BURROW_APP_DIR:-${PORTKEEPER_APP_DIR:-$HOME/Applications/${APP_NAME}.app}}"
SIGNING_IDENTITY="${SIGNING_IDENTITY:--}"
BUILD_CONFIGURATION="${BUILD_CONFIGURATION:-release}"

echo "Building ${APP_NAME} (${BUILD_CONFIGURATION})..."
swift build \
  --package-path "$ROOT_DIR" \
  -c "$BUILD_CONFIGURATION" \
  --product BurrowApp

BIN_DIR="$(swift build --package-path "$ROOT_DIR" -c "$BUILD_CONFIGURATION" --show-bin-path)"
SOURCE_BINARY="${BIN_DIR}/BurrowApp"

if [ ! -x "$SOURCE_BINARY" ]; then
  echo "error: built binary not found at $SOURCE_BINARY" >&2
  exit 1
fi

if [ -d "$APP_DIR" ]; then
  RUNNING_PID="$(pgrep -f "$APP_DIR/Contents/MacOS/${EXECUTABLE_NAME}" || true)"
  if [ -n "$RUNNING_PID" ]; then
    echo "Stopping running ${APP_NAME} app..."
    kill $RUNNING_PID || true
    sleep 1
  fi
  rm -rf "$APP_DIR"
fi

mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "$SOURCE_BINARY" "$APP_DIR/Contents/MacOS/${EXECUTABLE_NAME}"
chmod 755 "$APP_DIR/Contents/MacOS/${EXECUTABLE_NAME}"
cp "$ROOT_DIR/XcodeSupport/Burrow.icns" "$APP_DIR/Contents/Resources/Burrow.icns"

cat > "$APP_DIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleExecutable</key>
  <string>${EXECUTABLE_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>${BUNDLE_ID}</string>
  <key>CFBundleIconFile</key>
  <string>Burrow</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF

/usr/bin/codesign \
  --force \
  --deep \
  --sign "$SIGNING_IDENTITY" \
  --timestamp=none \
  "$APP_DIR"

echo "Installed ${APP_NAME} to ${APP_DIR}"
echo "Bundle identifier: ${BUNDLE_ID}"
if [ "$SIGNING_IDENTITY" = "-" ]; then
  echo "Signing: ad-hoc"
else
  echo "Signing identity: ${SIGNING_IDENTITY}"
fi
