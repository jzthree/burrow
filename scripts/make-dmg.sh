#!/bin/zsh
#
# Builds a self-contained, notarized Burrow.dmg: the app plus openconnect,
# ocproxy and their dylib closure, so a user needs no Homebrew install.
#
# One-time setup (Apple Developer Program required):
#   1. Create a "Developer ID Application" certificate at developer.apple.com
#      (Certificates → +) and double-click the download to add it to your
#      login keychain.
#   2. Store notarization credentials once:
#        xcrun notarytool store-credentials burrow-notary \
#          --apple-id you@example.com --team-id 5AD7QB9795 \
#          --password <app-specific-password>     # from appleid.apple.com
#
# Usage:
#   scripts/make-dmg.sh [version]
# Env overrides:
#   DEVELOPER_ID="Developer ID Application: Name (TEAMID)"  (else auto-detected)
#   NOTARY_PROFILE=burrow-notary
#   ALLOW_DEV_SIGN=1   # sign with Apple Development + skip notarize (local test)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_NAME="Burrow"
BUNDLE_ID="com.jianzhou.burrow"
TEAM_ID="5AD7QB9795"
NOTARY_PROFILE="${NOTARY_PROFILE:-burrow-notary}"
VERSION="${1:-$(git -C "$ROOT_DIR" describe --tags --always 2>/dev/null || echo 0.0.0)}"

STAGE="$ROOT_DIR/build/dmg"
APP_DIR="$STAGE/${APP_NAME}.app"
DMG_OUT="$ROOT_DIR/build/${APP_NAME}-${VERSION}.dmg"
HELPER_ENTITLEMENTS="$ROOT_DIR/build/helper.entitlements"

note()  { print -P "%F{cyan}==>%f $*"; }
fail()  { print -P "%F{red}error:%f $*" >&2; exit 1; }

# --- locate tooling ---------------------------------------------------------
for tool in dylibbundler create-dmg; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool not found. Install build tools: brew install dylibbundler create-dmg"
done
BREW="$(command -v brew)" || fail "Homebrew is required to source openconnect/ocproxy."

OPENCONNECT_SRC="$(command -v openconnect)" || fail "openconnect not installed (brew install openconnect)."
OCPROXY_SRC="$(command -v ocproxy)" || fail "ocproxy not installed (brew install ocproxy)."
HIPREPORT_SRC="$("$BREW" --prefix openconnect 2>/dev/null)/libexec/openconnect/hipreport.sh"

# --- choose signing identity ------------------------------------------------
SKIP_NOTARIZE=0
if [ -z "${DEVELOPER_ID:-}" ]; then
  DEVELOPER_ID="$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/{print $2; exit}')"
fi
if [ -z "${DEVELOPER_ID:-}" ]; then
  if [ "${ALLOW_DEV_SIGN:-0}" = "1" ]; then
    DEVELOPER_ID="$(security find-identity -v -p codesigning | awk -F'"' '/Apple Development/{print $2; exit}')"
    SKIP_NOTARIZE=1
    note "No Developer ID cert; ALLOW_DEV_SIGN set → signing with '$DEVELOPER_ID' and skipping notarization (local test only)."
  else
    fail "No 'Developer ID Application' certificate found. Create one at developer.apple.com (see header), or set ALLOW_DEV_SIGN=1 for a local, non-notarized test build."
  fi
fi
note "Signing identity: $DEVELOPER_ID"
note "Building $APP_NAME $VERSION"

# --- build ------------------------------------------------------------------
swift build --package-path "$ROOT_DIR" -c release --product BurrowApp
BIN_DIR="$(swift build --package-path "$ROOT_DIR" -c release --show-bin-path)"
[ -x "$BIN_DIR/BurrowApp" ] || fail "built binary not found at $BIN_DIR/BurrowApp"

# --- assemble the .app ------------------------------------------------------
rm -rf "$STAGE"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources" \
         "$APP_DIR/Contents/Helpers" "$APP_DIR/Contents/Frameworks"

cp "$BIN_DIR/BurrowApp" "$APP_DIR/Contents/MacOS/${APP_NAME}"
chmod 755 "$APP_DIR/Contents/MacOS/${APP_NAME}"
cp "$ROOT_DIR/XcodeSupport/Burrow.icns" "$APP_DIR/Contents/Resources/Burrow.icns"

cat > "$APP_DIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleDisplayName</key><string>${APP_NAME}</string>
  <key>CFBundleExecutable</key><string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundleIconFile</key><string>Burrow</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>${APP_NAME}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

# --- bundle the VPN helpers + their dylib closure ---------------------------
note "Bundling openconnect + ocproxy and dependencies"
cp "$OPENCONNECT_SRC" "$APP_DIR/Contents/Helpers/openconnect"
cp "$OCPROXY_SRC" "$APP_DIR/Contents/Helpers/ocproxy"
# The HIP script is not Mach-O, so it lives in Resources (sealed as data);
# Helpers holds only signable binaries.
if [ -f "$HIPREPORT_SRC" ]; then
  cp "$HIPREPORT_SRC" "$APP_DIR/Contents/Resources/hipreport.sh"
  chmod 755 "$APP_DIR/Contents/Resources/hipreport.sh"
else
  note "hipreport.sh not found at $HIPREPORT_SRC — GlobalProtect HIP reports won't be bundled."
fi
chmod 755 "$APP_DIR/Contents/Helpers/openconnect" "$APP_DIR/Contents/Helpers/ocproxy"

# dylibbundler copies the transitive dylib closure into Frameworks and rewrites
# every load command to @executable_path/../Frameworks. Helpers live in
# Contents/Helpers, so ../Frameworks resolves correctly.
dylibbundler -of -b \
  -x "$APP_DIR/Contents/Helpers/openconnect" \
  -x "$APP_DIR/Contents/Helpers/ocproxy" \
  -d "$APP_DIR/Contents/Frameworks" \
  -p "@executable_path/../Frameworks"

# --- code sign (inside-out, hardened runtime, secure timestamp) -------------
cat > "$HELPER_ENTITLEMENTS" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <!-- The helpers load the bundled GnuTLS/crypto dylibs. -->
  <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict>
</plist>
EOF

TS_FLAG=(--timestamp)
[ "$SKIP_NOTARIZE" = "1" ] && TS_FLAG=(--timestamp=none)

note "Signing dylibs"
find "$APP_DIR/Contents/Frameworks" -type f -name '*.dylib' -print0 | while IFS= read -r -d '' lib; do
  codesign --force --options runtime "${TS_FLAG[@]}" --sign "$DEVELOPER_ID" "$lib"
done

note "Signing helpers"
for helper in openconnect ocproxy; do
  codesign --force --options runtime "${TS_FLAG[@]}" \
    --entitlements "$HELPER_ENTITLEMENTS" --sign "$DEVELOPER_ID" \
    "$APP_DIR/Contents/Helpers/$helper"
done

note "Signing app"
codesign --force --options runtime "${TS_FLAG[@]}" --sign "$DEVELOPER_ID" "$APP_DIR"
codesign --verify --deep --strict --verbose=2 "$APP_DIR"

# --- build the DMG ----------------------------------------------------------
note "Building DMG"
rm -f "$DMG_OUT"
create-dmg \
  --volname "${APP_NAME} ${VERSION}" \
  --app-drop-link 480 170 \
  --icon "${APP_NAME}.app" 170 170 \
  --window-size 660 360 \
  --no-internet-enable \
  "$DMG_OUT" "$APP_DIR" || {
    # create-dmg returns non-zero if it can't set a custom icon layout in
    # headless contexts; fall back to a plain image so CI still produces output.
    note "create-dmg fancy layout failed; building a plain DMG with hdiutil."
    hdiutil create -volname "${APP_NAME} ${VERSION}" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG_OUT"
  }

# --- notarize + staple ------------------------------------------------------
if [ "$SKIP_NOTARIZE" = "1" ]; then
  note "Skipped notarization (dev-signed). The DMG runs on this Mac; other Macs will block it."
else
  if xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
    note "Submitting to notary service (this can take a few minutes)…"
    xcrun notarytool submit "$DMG_OUT" --keychain-profile "$NOTARY_PROFILE" --wait
    note "Stapling"
    xcrun stapler staple "$DMG_OUT"
    spctl -a -t open --context context:primary-signature -vv "$DMG_OUT" || true
  else
    note "No notarytool profile '$NOTARY_PROFILE' found — DMG is signed but NOT notarized."
    note "Set it up once (see header), then re-run, or: xcrun notarytool submit \"$DMG_OUT\" --keychain-profile $NOTARY_PROFILE --wait && xcrun stapler staple \"$DMG_OUT\""
  fi
fi

note "Done: $DMG_OUT"
