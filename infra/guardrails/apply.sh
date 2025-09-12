#!/bin/sh
set -eu

# --- ipsets ---
ipset create decoy_net hash:net 2>/dev/null || true
ipset add decoy_net 10.20.0.0/16 2>/dev/null || true

ipset create shun hash:ip timeout 3600 2>/dev/null || true

# ---------- DOCKER-USER ----------
# ensure chain ends with RETURN so our inserts go above it
iptables -C DOCKER-USER -j RETURN 2>/dev/null || iptables -I DOCKER-USER -j RETURN

# remove stale copies (keeps script idempotent)
for p in udp tcp; do
  iptables -D DOCKER-USER -m set --match-set decoy_net src -p $p --dport 53 -j ACCEPT 2>/dev/null || true
done
iptables -D DOCKER-USER -m set --match-set decoy_net src -p udp --dport 123 -j ACCEPT 2>/dev/null || true
iptables -D DOCKER-USER -m set --match-set decoy_net src -j DROP 2>/dev/null || true

# insert ALLOWs first, then DROP (top to bottom)
iptables -I DOCKER-USER 1 -m set --match-set decoy_net src -p udp --dport 123 -j ACCEPT 2>/dev/null || true  # NTP (optional)
iptables -I DOCKER-USER 2 -m set --match-set decoy_net src -p udp --dport 53  -j ACCEPT
iptables -I DOCKER-USER 3 -m set --match-set decoy_net src -p tcp --dport 53  -j ACCEPT
iptables -I DOCKER-USER 4 -m set --match-set decoy_net src -j DROP

# ---------- FORWARD ----------
# keep shun first
iptables -C FORWARD -m set --match-set shun src -j DROP 2>/dev/null || iptables -I FORWARD 1 -m set --match-set shun src -j DROP

# remove stale decoy rules
for p in udp tcp; do
  iptables -D FORWARD -m set --match-set decoy_net src -p $p --dport 53 -j ACCEPT 2>/dev/null || true
done
iptables -D FORWARD -m set --match-set decoy_net src -p udp --dport 123 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -m set --match-set decoy_net src -j DROP 2>/dev/null || true

# insert in correct order (after shun)
iptables -I FORWARD 2 -m set --match-set decoy_net src -p udp --dport 123 -j ACCEPT 2>/dev/null || true
iptables -I FORWARD 3 -m set --match-set decoy_net src -p udp --dport 53  -j ACCEPT
iptables -I FORWARD 4 -m set --match-set decoy_net src -p tcp --dport 53  -j ACCEPT
iptables -I FORWARD 5 -m set --match-set decoy_net src -j DROP

echo "[OK] Guardrails applied: decoy_net egress limited to DNS(+NTP), shun active."