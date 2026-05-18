#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  BAZTA — Attack Demo Scripts for Mininet Hosts
#  Run these INSIDE Mininet CLI, e.g.:
#    mininet> h1 bash attacks.sh icmp_flood h2
# ══════════════════════════════════════════════════════════════

set -e

ACTION="${1:-help}"
TARGET="${2:-10.0.0.2}"
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

    full_demo)
        echo "═══════════════════════════════════════════"
        echo "  BAZTA Full Demo Scenario"
        echo "  Target: $TARGET"
        echo "═══════════════════════════════════════════"
        echo ""

        echo "[1/4] Normal traffic (ping for 10s)..."
        ping -c 10 -i 1 "$TARGET" >/dev/null 2>&1 || true
        echo "      ✓ Normal phase done"
        sleep 2

        echo "[2/4] ICMP Flood attack (15s)..."
        timeout 15 hping3 -1 -i u1000 --icmp "$TARGET" >/dev/null 2>&1 || true
        echo "      ✓ ICMP flood done — check dashboard for BLOCK"
        sleep 5

        echo "[3/4] Port Scan attack..."
        nmap "${NMAP_FAST_FLAGS[@]}" --top-ports "$SCAN_PORTS" "$TARGET" >/dev/null 2>&1 || true
        echo "      ✓ Port scan done — check dashboard for detection"
        sleep 5

        echo "[4/4] Recovery period (normal ping 15s)..."
        ping -c 15 -i 1 "$TARGET" >/dev/null 2>&1 || true
        echo "      ✓ Recovery done — trust score should climb back"

        echo ""
        echo "═══════════════════════════════════════════"
        echo "  Demo complete! Check the dashboard."
        echo "═══════════════════════════════════════════"
        ;;

    help|*)
        echo "BAZTA Attack Demo Scripts"
        echo "Usage: bash attacks.sh <action> <target_ip>"
        echo ""
        echo "Actions:"
        echo "  icmp_flood   — ICMP flood (hping3, 30s)"
        echo "  port_scan    — SYN scan (nmap, top ${SCAN_PORTS}; set SCAN_PORTS=N to override)"
        echo "  byte_flood   — Large-packet flood (hping3, 30s)"
        echo "  full_demo    — Full scenario: normal → flood → scan → recovery"
        echo ""
        echo "Example:"
        echo "  mininet> h1 bash attacks.sh icmp_flood 10.0.1.2"
        echo "  mininet> h1 bash attacks.sh full_demo 10.0.1.2"
        ;;
esac
