#!/usr/bin/env bash
# Targets bash on the Oracle VM (Ubuntu 24.04), run as root by mivais-deploy.timer every two
# minutes. Moves the checkout to the fork's deploy/oracle branch and, when that changed, when
# Studio is not running (the first run) or with --force, rebuilds and restarts the stack in
# compose.yml. The checkout under
# /opt/mivais is managed by this script only, so it follows the branch even after a force
# push. Output goes to the journal: journalctl -u mivais-deploy.
set -euo pipefail

REPO=/opt/mivais/MIVAIS
BRANCH=deploy/oracle
COMPOSE=(docker compose -f "$REPO/studio/deploy/oracle/compose.yml")

cd "$REPO"
git fetch --quiet origin "$BRANCH"
before=$(git rev-parse HEAD)
after=$(git rev-parse "origin/$BRANCH")
running=$("${COMPOSE[@]}" ps --quiet studio)
if [[ "$before" == "$after" && -n "$running" && "${1:-}" != "--force" ]]; then
  exit 0
fi

git reset --quiet --hard "origin/$BRANCH"
echo "Deploying $(git log --oneline -1)"
"${COMPOSE[@]}" up --detach --build --remove-orphans
docker image prune --force >/dev/null
echo "Deployed $(git rev-parse --short HEAD)"
