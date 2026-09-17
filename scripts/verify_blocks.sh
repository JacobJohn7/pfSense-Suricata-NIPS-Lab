#!/bin/sh
# verify_blocks.sh - Helper script for pfSense shell to inspect Suricata IPS block list
# Execute on pfSense shell (SSH Option 8 or diagnostics)

echo "=================================================="
echo " pfSense Suricata IPS Blocked Hosts (table: snort2c)"
echo "=================================================="

# Check if snort2c pf table exists and list blocked IP addresses
if pfctl -t snort2c -T show >/dev/null 2>&1; then
    echo "[+] Currently Blocked IP Addresses:"
    pfctl -t snort2c -T show
    echo ""
    echo "[+] Total Blocked Count: $(pfctl -t snort2c -T show | wc -l | tr -d ' ')"
else
    echo "[!] Table 'snort2c' not found. Ensure Suricata Blocking is enabled on LAN interface."
fi

echo ""
echo "[+] Recent Suricata Drop Events (alerts.log):"
tail -n 10 /var/log/suricata/suricata_em1/alerts.log 2>/dev/null || echo "[!] Suricata log file not found."
