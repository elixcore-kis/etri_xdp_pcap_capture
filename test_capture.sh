#!/bin/bash

echo "=== XDP Packet Capture Test ==="
echo "Testing packet capture on ens20"

# Clean up any existing captures
rm -f test_capture.pcap

# Start packet capture in background
echo "Starting XDP packet capture..."
sudo timeout 15 ./capture_main ens20 test_capture.pcap &
CAPTURE_PID=$!

# Wait for XDP to load
sleep 3

# Generate some test traffic
echo "Generating test traffic on ens20..."
ping -I ens20 -c 5 8.8.8.8 > /dev/null 2>&1 &
curl -s --interface ens20 http://google.com > /dev/null 2>&1 &

# Wait for capture to finish
wait $CAPTURE_PID

echo "=== Capture Results ==="
if [ -f test_capture.pcap ]; then
    echo "PCAP file created: test_capture.pcap"
    echo "File size: $(ls -lh test_capture.pcap | awk '{print $5}')"
    
    # Try to analyze with tcpdump if available
    if command -v tcpdump >/dev/null 2>&1; then
        echo "First few packets:"
        tcpdump -r test_capture.pcap -n -c 5 2>/dev/null || echo "No packets in file"
    fi
else
    echo "No PCAP file created"
fi

echo "=== Interface Statistics ==="
echo "ens20 RX packets: $(cat /sys/class/net/ens20/statistics/rx_packets)"
echo "ens20 TX packets: $(cat /sys/class/net/ens20/statistics/tx_packets)"