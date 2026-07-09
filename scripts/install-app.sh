#!/bin/zsh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_NAME="Burrow"
EXECUTABLE_NAME="Burrow"
BUNDLE_ID="${BURROW_BUNDLE_ID:-com.jianzhou.burrow}"
APP_DIR="${BURROW_APP_DIR:-${PORTKEEPER_APP_DIR:-$HOME/Applications/${APP_NAME}.app}}"
# Prefer a stable signing identity so Keychain "Always Allow" decisions
# survive rebuilds; ad-hoc signing gives the app a new identity every build,
# which re-triggers password prompts on each update.
if [ -z "${SIGNING_IDENTITY:-}" ]; then
  SIGNING_IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null | awk -F'"' '/Apple Development/{print $2; exit}')"
fi
SIGNING_IDENTITY="${SIGNING_IDENTITY:--}"
BUILD_CONFIGURATION="${BUILD_CONFIGURATION:-release}"
# Stamp the actual build (tag or commit) so installs are distinguishable;
# a hardcoded "1.0" would make every source build claim the same version.
VERSION="$(git -C "$ROOT_DIR" describe --tags --always 2>/dev/null || echo 0.0.0)"

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
    /usr/bin/osascript -e "tell application id \"${BUNDLE_ID}\" to quit" >/dev/null 2>&1 || true
    for _ in {1..20}; do
      RUNNING_PID="$(pgrep -f "$APP_DIR/Contents/MacOS/${EXECUTABLE_NAME}" || true)"
      [ -z "$RUNNING_PID" ] && break
      sleep 0.2
    done
    RUNNING_PID="$(pgrep -f "$APP_DIR/Contents/MacOS/${EXECUTABLE_NAME}" || true)"
    if [ -n "$RUNNING_PID" ]; then
      kill $RUNNING_PID || true
      sleep 1
    fi
  fi
  rm -rf "$APP_DIR"
fi

mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "$SOURCE_BINARY" "$APP_DIR/Contents/MacOS/${EXECUTABLE_NAME}"
chmod 755 "$APP_DIR/Contents/MacOS/${EXECUTABLE_NAME}"
cp "$ROOT_DIR/XcodeSupport/Burrow.icns" "$APP_DIR/Contents/Resources/Burrow.icns"

# Patched ocproxy (upstream-packet backpressure — see vendor/ocproxy/README.md):
# bundling it into Contents/Helpers makes GatewaySupport.ocproxyPath() prefer it
# over any Homebrew install. Stock ocproxy drops upstream packets when the
# openconnect socketpair fills (~2 datagrams on macOS), collapsing VPN uploads
# to ~60KB/s; the patched build queues + flushes instead (measured 31-60x).
VENDORED_OCPROXY="$ROOT_DIR/vendor/ocproxy/ocproxy-macos-$(uname -m)"
if [ -x "$VENDORED_OCPROXY" ]; then
  mkdir -p "$APP_DIR/Contents/Helpers"
  cp "$VENDORED_OCPROXY" "$APP_DIR/Contents/Helpers/ocproxy"
  chmod 755 "$APP_DIR/Contents/Helpers/ocproxy"
  echo "Bundled patched ocproxy into Contents/Helpers"
fi

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
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF

# Sign inside-out (no deprecated --deep): nested helpers first, then the app,
# matching make-dmg.sh.
if [ -x "$APP_DIR/Contents/Helpers/ocproxy" ]; then
  /usr/bin/codesign \
    --force \
    --sign "$SIGNING_IDENTITY" \
    --timestamp=none \
    "$APP_DIR/Contents/Helpers/ocproxy"
fi
/usr/bin/codesign \
  --force \
  --sign "$SIGNING_IDENTITY" \
  --timestamp=none \
  "$APP_DIR"

# --- burrow CLI ---------------------------------------------------------
# The app is only half the product; put the CLI on the user's PATH too.
CLI_INSTALL_DIR="${BURROW_BIN_DIR:-$HOME/.local/bin}"
echo "Building burrow CLI..."
swift build --package-path "$ROOT_DIR" -c "$BUILD_CONFIGURATION" --product burrow
mkdir -p "$CLI_INSTALL_DIR"
# Remove before copying: overwriting a signed Mach-O in place leaves the
# kernel's stale signature verdict on the inode, and macOS then SIGKILLs
# the binary on launch (exit 137) with no error message.
rm -f "$CLI_INSTALL_DIR/burrow"
cp "${BIN_DIR}/burrow" "$CLI_INSTALL_DIR/burrow"
chmod 755 "$CLI_INSTALL_DIR/burrow"
echo "Installed burrow CLI to ${CLI_INSTALL_DIR}/burrow"
case ":$PATH:" in
  *":$CLI_INSTALL_DIR:"*) ;;
  *)
    echo "note: ${CLI_INSTALL_DIR} is not on your PATH. Add this to ~/.zprofile:"
    echo "  export PATH=\"${CLI_INSTALL_DIR}:\$PATH\""
    ;;
esac

echo "Installed ${APP_NAME} to ${APP_DIR}"
echo "Bundle identifier: ${BUNDLE_ID}"
if [ "$SIGNING_IDENTITY" = "-" ]; then
  echo "Signing: ad-hoc"
else
  echo "Signing identity: ${SIGNING_IDENTITY}"
fi
