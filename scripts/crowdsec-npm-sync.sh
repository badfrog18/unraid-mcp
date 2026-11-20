#!/bin/bash
# crowdsec-npm-sync – überträgt CrowdSec-Sperren als nginx-geo-Tabelle in Nginx Proxy Manager.
# Gedacht für das Unraid-Plugin "User Scripts", Zeitplan z.B. */5 * * * *
#
# Ablauf: Sperren holen -> Datei bauen -> nur bei Änderung: nginx -t, reload.
# Schlägt etwas fehl, bleibt die bisherige Liste aktiv.

set -o pipefail

CS_CONTAINER="${CS_CONTAINER:-crowdsec}"
NPM_CONTAINER="${NPM_CONTAINER:-Nginx-Proxy-Manager-Official}"
CUSTOM_DIR="${CUSTOM_DIR:-/mnt/user/appdata/Nginx-Proxy-Manager-Official/data/nginx/custom}"
GEO_FILE="$CUSTOM_DIR/crowdsec_geo.conf"
MIN_ENTRIES="${MIN_ENTRIES:-1}"   # weniger Einträge = vermutlich Fehler -> nichts ändern

log() { echo "$(date '+%F %T') crowdsec-npm-sync: $*"; logger -t crowdsec-npm-sync "$*" 2>/dev/null; }

TMP_RAW="$(mktemp)"; TMP_GEO="$(mktemp)"
trap 'rm -f "$TMP_RAW" "$TMP_GEO"' EXIT

if ! docker exec "$CS_CONTAINER" cscli decisions list -a -o raw > "$TMP_RAW" 2>/dev/null; then
  log "FEHLER: cscli nicht erreichbar – Liste bleibt unverändert"; exit 1
fi

# Spalten: id,source,ip,reason,action,country,as,events_count,expiration,simulated,alert_id
# Nur aktive Bans (Restlaufzeit nicht negativ, nicht simuliert), Scope Ip oder Range.
awk -F, 'NR > 1 && $5 == "ban" && $9 !~ /^-/ && $10 != "true" {
    scope = $3; sub(/:.*/, "", scope)
    value = $3; sub(/^[^:]*:/, "", value)
    if (scope == "Ip" || scope == "Range") print value
}' "$TMP_RAW" \
  | grep -E '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$' \
  | sort -u > "$TMP_RAW.list"

COUNT=$(wc -l < "$TMP_RAW.list")
if [ "$COUNT" -lt "$MIN_ENTRIES" ]; then
  log "WARNUNG: nur $COUNT Sperren gefunden – Liste bleibt unverändert"; rm -f "$TMP_RAW.list"; exit 1
fi

{
  echo "# Automatisch erzeugt von crowdsec-npm-sync – nicht von Hand bearbeiten"
  echo "geo \$crowdsec_banned {"
  echo "    default 0;"
  sed 's/.*/    & 1;/' "$TMP_RAW.list"
  echo "}"
} > "$TMP_GEO"
rm -f "$TMP_RAW.list"

if [ -f "$GEO_FILE" ] && cmp -s "$TMP_GEO" "$GEO_FILE"; then
  exit 0   # keine Änderung, kein Reload
fi

mkdir -p "$CUSTOM_DIR"
[ -f "$GEO_FILE" ] && cp "$GEO_FILE" "$GEO_FILE.prev"
cp "$TMP_GEO" "$GEO_FILE"

if docker exec "$NPM_CONTAINER" nginx -t >/dev/null 2>&1; then
  docker exec "$NPM_CONTAINER" nginx -s reload >/dev/null 2>&1
  log "$COUNT Sperren aktiv, nginx neu geladen"
else
  log "FEHLER: nginx -t fehlgeschlagen – vorherige Liste wiederhergestellt"
  if [ -f "$GEO_FILE.prev" ]; then cp "$GEO_FILE.prev" "$GEO_FILE"; else rm -f "$GEO_FILE"; fi
  exit 1
fi
