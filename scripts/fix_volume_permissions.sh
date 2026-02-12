#!/bin/sh
set -eu

APP_UID="${APP_UID:-100}"
APP_GID="${APP_GID:-101}"

volumes="ti_briefing-data ti_readwise-state ti_zotero-state ti_enrich-text-state ti_cvelist-state ti_mapping-data"

for volume in $volumes; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    docker run --rm -v "${volume}:/data" --entrypoint chown alpine:latest -R "${APP_UID}:${APP_GID}" /data
  else
    echo "Skipping missing volume: ${volume}"
  fi
done
