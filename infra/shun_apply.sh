#!/bin/sh
set -eu

SET=${IPSET_NAME:-shun}
TTL=${BLOCK_TTL:-3600}
QDIR=${QUEUE_DIR:-/queue}

# tools
apk add --no-cache ipset iptables >/dev/null 2>&1 || true

# ensure set exists
ipset list "$SET" >/dev/null 2>&1 || ipset create "$SET" hash:ip timeout "$TTL"

echo "[shun_apply] watching $QDIR (set=$SET ttl=$TTL)"

mkdir -p "$QDIR"

while true; do
  for f in "$QDIR"/ban-*.txt; do
    [ -f "$f" ] || break
    line=$(tr -d '\r\n' < "$f")
    ip="$line"
    # accept JSON like {"ip":"1.2.3.4","ttl":3600}
    case "$line" in
      \{*\} )
        ip=$(echo "$line" | sed -n 's/.*"ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        t=$(echo "$line" | sed -n 's/.*"ttl"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p')
        [ -n "$t" ] && TTL="$t"
        ;;
    esac

    if [ -n "$ip" ]; then
      ipset add "$SET" "$ip" -exist timeout "$TTL" && echo "[shun_apply] shunned $ip for $TTL s"
    fi
    rm -f "$f" || echo "[shun_apply] warn: could not remove $f"
  done
  sleep 2
done