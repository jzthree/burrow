#!/bin/zsh
#
# Deploys the Burrow landing site (docs/) to Cloudflare Pages, hosting the
# latest built DMG at /downloads/Burrow.dmg so the site's download button works.
#
# The DMG is copied in at deploy time (and git-ignored) — uploaded to Cloudflare
# but never committed, so the repo stays free of binaries.
#
# First-time setup:
#   1. Build a notarized DMG once: scripts/make-dmg.sh 1.0.0
#   2. Create the Pages project + add the custom domain (one time):
#        npx wrangler pages project create burrow --production-branch main
#        # then in the Cloudflare dashboard: Pages → burrow → Custom domains →
#        # add  burrow.ideaxlab.net  (auto-creates the CNAME since you own the zone)
#
# Usage:
#   scripts/deploy-site.sh
# Env:
#   CF_PAGES_PROJECT=burrow   # Cloudflare Pages project name

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="${CF_PAGES_PROJECT:-burrow}"

DMG="$(ls -t "$ROOT_DIR"/build/Burrow-*.dmg 2>/dev/null | head -1 || true)"
mkdir -p "$ROOT_DIR/docs/downloads"
if [ -n "$DMG" ]; then
  # The site claims a notarized download; refuse to ship one that isn't.
  # (ALLOW_UNNOTARIZED=1 overrides for a staging deploy.)
  if ! xcrun stapler validate "$DMG" >/dev/null 2>&1; then
    if [ "${ALLOW_UNNOTARIZED:-0}" = "1" ]; then
      echo "warning: $(basename "$DMG") is NOT notarized — deploying anyway (ALLOW_UNNOTARIZED=1)."
    else
      echo "error: $(basename "$DMG") is not notarized (stapler validate failed)." >&2
      echo "       Gatekeeper will block it on other Macs, and the site says 'notarized'." >&2
      echo "       Build with scripts/make-dmg.sh (Developer ID + notary profile)," >&2
      echo "       or set ALLOW_UNNOTARIZED=1 to deploy anyway." >&2
      exit 1
    fi
  fi
  cp "$DMG" "$ROOT_DIR/docs/downloads/Burrow.dmg"
  echo "Staged $(basename "$DMG") → docs/downloads/Burrow.dmg ($(du -h "$DMG" | cut -f1))"
elif [ "${ALLOW_MISSING_DMG:-0}" = "1" ]; then
  echo "warning: no build/Burrow-*.dmg found — deploying with a dead download link (ALLOW_MISSING_DMG=1)."
else
  echo "error: no build/Burrow-*.dmg found — the download buttons would 404." >&2
  echo "       Run scripts/make-dmg.sh first, or set ALLOW_MISSING_DMG=1 to deploy anyway." >&2
  exit 1
fi

echo "Deploying docs/ to Cloudflare Pages project '$PROJECT'…"
npx --yes wrangler@latest pages deploy "$ROOT_DIR/docs" --project-name "$PROJECT"
echo "Done. If the custom domain is attached, it's live at https://burrow.ideaxlab.net"
