#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  BAZTA — Attack Demo Scripts for Mininet Hosts
#  Run these INSIDE Mininet CLI, e.g.:
#    mininet> h1 bash attacks.sh icmp_flood h2
# ══════════════════════════════════════════════════════════════

set -e

ACTION="${1:-help}"
TARGET="${2:-10.0.1.2}"

# Resolve hostnames to IPs
case "$TARGET" in
    h1) TARGET="10.0.1.1" ;;
    h2) TARGET="10.0.1.2" ;;
    h3) TARGET="10.0.2.1" ;;
    h4) TARGET="10.0.2.2" ;;
    h5) TARGET="10.0.3.1" ;;
    h6) TARGET="10.0.3.2" ;;
esac

# Prevent self-flooding/loopback traffic which won't traverse the switch
LOCAL_IP=$(hostname -I | awk '{print $1}')
if [ "$TARGET" = "$LOCAL_IP" ]; then
    if [ "$LOCAL_IP" = "10.0.1.1" ]; then
        TARGET="10.0.1.2"
    else
        TARGET="10.0.1.1"
    fi
    echo "[INFO] Target was set to local IP ($LOCAL_IP). Changed target to $TARGET to ensure traffic traverses the switch."
fi

SCAN_PORTS="${SCAN_PORTS:-30}"
NMAP_FAST_FLAGS=(-sS -T5 -n -Pn --max-retries 1 --host-timeout 15s)

case "$ACTION" in

    icmp_flood)
        echo "[ATTACK] ICMP Flood → $TARGET (hping3, 1000 pkt/s for 30s)"
        timeout 30 hping3 -1 -i u1000 --icmp "$TARGET" 2>/dev/null || true
        echo "[DONE] ICMP flood stopped."
        ;;

    port_scan)
        echo "[ATTACK] SYN Port Scan → $TARGET (nmap top $SCAN_PORTS ports, fast demo)"
        nmap "${NMAP_FAST_FLAGS[@]}" --top-ports "$SCAN_PORTS" "$TARGET" 2>/dev/null || true
        echo "[DONE] Port scan complete."
        ;;

    byte_flood)
        echo "[ATTACK] Byte Flood → $TARGET (hping3, 1400-byte packets)"
        timeout 30 hping3 --flood -d 1400 -p 80 "$TARGET" 2>/dev/null || true
        echo "[DONE] Byte flood stopped."
        ;;

    covert_channel)
        echo "[ATTACK] Covert Channel (Extreme Size Variance) → $TARGET"
        echo "         (15 pps, alternating 78-byte and 1428-byte packets)"
        END_TIME=$((SECONDS + 30))
        while [ $SECONDS -lt $END_TIME ]; do
            hping3 -2 -c 1 -d 50 -p 8080 "$TARGET" >/dev/null 2>&1 || true
            sleep 0.06
            hping3 -2 -c 1 -d 1400 -p 8080 "$TARGET" >/dev/null 2>&1 || true
            sleep 0.06
        done
        echo "[DONE] Covert channel stopped."
        ;;

    atypical_proto)
        echo "[ATTACK] Atypical Protocol Communication (GRE) → $TARGET"
        echo "         (5 pps, 80-byte packets, IP Proto 47)"
        timeout 30 hping3 --rawip -H 47 -d 60 -i u200000 "$TARGET" 2>/dev/null || true
        echo "[DONE] Atypical protocol stopped."
        ;;

    help|*)
        echo "BAZTA Attack Demo Scripts"
        echo "Usage: bash attacks.sh <action> <target_ip>"
        echo ""
        echo "Actions:"
        echo "  icmp_flood     — ICMP flood (hping3, 30s)"
        echo "  port_scan      — SYN scan (nmap, top ${SCAN_PORTS}; set SCAN_PORTS=N to override)"
        echo "  byte_flood     — Large-packet flood (hping3, 30s)"
        echo "  covert_channel — Alternating packet sizes (high variance → triggers RATE_LIMIT)"
        echo "  atypical_proto — GRE IP Protocol 47 (triggers RATE_LIMIT)"
        echo ""
        echo "Example:"
        echo "  mininet> h1 bash attacks.sh icmp_flood 10.0.1.2"
        echo "  mininet> h1 bash attacks.sh covert_channel 10.0.1.2"
        ;;
esac
