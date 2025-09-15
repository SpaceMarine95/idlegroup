#!/bin/sh
set -eu

# Config (env overrides)
SET="${IPSET_NAME:-shun}"
DEFAULT_TTL="${BLOCK_TTL:-3600}"
QDIR="${QUEUE_DIR:-/queue}"

# Tools (idempotent install; harmless if already present)
apk add --no-cache ipset iptables >/dev/null 2>&1 || true

# Ensure set exists (IPv4). Use -exist so reruns don't error.
ipset create "$SET" hash:ip family inet timeout "$DEFAULT_TTL" -exist

echo "[shun_apply] watching $QDIR (set=$SET ttl=$DEFAULT_TTL)"
mkdir -p "$QDIR"

# Clean exit on stop (optional)
trap 'echo "[shun_apply] exiting"; exit 0' TERM INT

inotifywait -m -e close_write,create,move "$QDIR" 2>/dev/null | while read -r _ _ path; do
  for f in "$QDIR"/ban-*.txt; do
    [ -f "$f" ] || continue
    # ... (your same per-file logic) ...
    rm -f "$f" || echo "[shun_apply] warn: could not remove $f"
  done
done