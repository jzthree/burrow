#!/bin/zsh
#
# Keep the three "Burrows" in lockstep: GitHub (origin), ~/Applications, and the
# running process are all the same commit after this runs.
#
#   scripts/sync.sh                 # tree must be clean; push HEAD, install, launch
#   scripts/sync.sh "commit message" # commit everything with that message first
#
# Refuses to sync a dirty tree without a message, so you never push a build that
# doesn't match its source. Pairs with install-app.sh's -dirty version stamp,
# which flags any build made from uncommitted changes.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

MESSAGE="${1:-}"

if [[ -n "$(git status --porcelain)" ]]; then
  if [[ -z "$MESSAGE" ]]; then
    print -u2 "error: working tree has uncommitted changes."
    print -u2 "       commit them yourself first, or run: scripts/sync.sh \"your commit message\""
    git status --short >&2
    exit 1
  fi
  print "Committing working tree…"
  git add -A
  git commit -m "$MESSAGE"
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
print "Pushing $BRANCH to origin…"
if git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
  git push
else
  git push -u origin "$BRANCH"
fi

print "Building + installing…"
./scripts/install-app.sh

print "Relaunching…"
/usr/bin/osascript -e 'tell application id "com.jianzhou.burrow" to quit' >/dev/null 2>&1 || true
sleep 1
open "$HOME/Applications/Burrow.app"

SHA="$(git rev-parse --short HEAD)"
print ""
print "Synced $SHA — GitHub, ~/Applications, and the running app now match."
