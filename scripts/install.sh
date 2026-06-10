#!/bin/bash
# Burrow one-line installer: clones (or updates) the source, builds the
# release app, installs it to ~/Applications/Burrow.app, and launches it.
#
#   curl -fsSL https://raw.githubusercontent.com/jzthree/Burrow/main/scripts/install.sh | bash
#
# Re-run any time to update. Requires the Xcode Command Line Tools
# (xcode-select --install) for git and swift.

set -euo pipefail

REPO_URL="${BURROW_REPO_URL:-https://github.com/jzthree/Burrow.git}"
SRC_DIR="${BURROW_SRC_DIR:-$HOME/.burrow/src}"

fail() {
  echo "error: $1" >&2
  exit 1
}

command -v git >/dev/null 2>&1 || fail "git not found — install the Xcode Command Line Tools first: xcode-select --install"
command -v swift >/dev/null 2>&1 || fail "swift not found — install the Xcode Command Line Tools first: xcode-select --install"

if [ -d "$SRC_DIR/.git" ]; then
  echo "Updating Burrow source in $SRC_DIR..."
  git -C "$SRC_DIR" pull --ff-only
else
  echo "Cloning Burrow into $SRC_DIR..."
  mkdir -p "$(dirname "$SRC_DIR")"
  git clone --depth 1 "$REPO_URL" "$SRC_DIR"
fi

"$SRC_DIR/scripts/install-app.sh"

open "$HOME/Applications/Burrow.app"

echo
echo "Burrow is running — look for the burrow icon in the menu bar."
echo "Optional, for VPN gateways: brew install openconnect ocproxy"
echo "(Burrow also offers to install these when you first connect a gateway.)"
