#!/bin/bash
#
# Capture Kerberos DCE/RPC traffic for analysis
# Usage: ./capture_pcap.sh <interface> <target_host> <output_file>
#
# Example: ./capture_pcap.sh en0 192.168.1.100 docs/captures/kerberos_dce.pcap

set -e

INTERFACE=${1:-en0}
TARGET=${2:-""}
OUTPUT=${3:-"docs/captures/kerberos_$(date +%Y%m%d_%H%M%S).pcap"}

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <interface> <target_host> [output_file]"
    echo "Example: $0 en0 192.168.1.100 docs/captures/kerberos_dce.pcap"
    exit 1
fi

# Create captures directory
mkdir -p "$(dirname "$OUTPUT")"

# Check for tshark/tcpdump
if command -v tshark >/dev/null 2>&1; then
    CAPTURE_CMD="tshark"
    echo "Using tshark for capture"
elif command -v tcpdump >/dev/null 2>&1; then
    CAPTURE_CMD="tcpdump"
    echo "Using tcpdump for capture"
else
    echo "Error: Neither tshark nor tcpdump found. Please install Wireshark or tcpdump."
    exit 1
fi

# Kerberos ports: 88 (KDC), 135 (EPM), 445 (SMB), 49152-65535 (dynamic RPC)
FILTER="host $TARGET and (port 88 or port 135 or port 445 or portrange 49152-65535)"

echo "==========================================="
echo "Kerberos DCE/RPC Packet Capture"
echo "==========================================="
echo "Interface: $INTERFACE"
echo "Target: $TARGET"
echo "Output: $OUTPUT"
echo "Filter: $FILTER"
echo ""
echo "Press Ctrl+C to stop capture..."
echo "==========================================="

if [ "$CAPTURE_CMD" = "tshark" ]; then
    # Tshark with detailed Kerberos and DCE/RPC dissection
    sudo tshark -i "$INTERFACE" \
        -f "$FILTER" \
        -w "$OUTPUT" \
        -P \
        -O kerberos,dcerpc,gss-api \
        2>&1 | while read line; do
            # Show packet summary
            echo "$line" | grep -E "(Kerberos|DCERPC|GSS-API|AS-REQ|AS-REP|TGS-REQ|TGS-REP|AP-REQ|AP-REP)"
        done
else
    # TCPdump fallback
    sudo tcpdump -i "$INTERFACE" \
        -w "$OUTPUT" \
        -s 0 \
        "$FILTER"
fi

echo ""
echo "Capture saved to: $OUTPUT"
echo ""
echo "To analyze:"
echo "  wireshark $OUTPUT &"
echo "  or"
echo "  tshark -r $OUTPUT -Y 'kerberos or dcerpc'"

# Generate summary if tshark is available
if command -v tshark >/dev/null 2>&1; then
    echo ""
    echo "Summary:"
    echo "--------"
    tshark -r "$OUTPUT" -q -z io,stat,0,"COUNT(kerberos)kerberos","COUNT(dcerpc)dcerpc","COUNT(gss-api)gss-api" 2>/dev/null || true

    echo ""
    echo "Kerberos message types:"
    tshark -r "$OUTPUT" -Y kerberos -T fields -e kerberos.msg_type 2>/dev/null | sort | uniq -c || true

    echo ""
    echo "DCE/RPC operations:"
    tshark -r "$OUTPUT" -Y dcerpc -T fields -e dcerpc.cn_opnum 2>/dev/null | sort | uniq -c || true
fi