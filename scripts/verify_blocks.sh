#!/bin/sh
# verify_blocks.sh - Helper script for pfSense shell to inspect Suricata IPS block list
# Execute on pfSense shell (SSH Option 8 or Diagnostics -> Command Prompt)

echo "=================================================="
echo " pfSense Suricata IPS Blocked Hosts (table: snort2c)"
echo "=================================================="

# Check if snort2c pf table exists and list blocked IP addresses
if pfctl -t snort2c -T show >/dev/null 2>&1; then
    echo "[+] Currently Blocked IP Addresses in pf kernel table:"
    pfctl -t snort2c -T show
    echo ""
    echo "[+] Total Blocked Entries: $(pfctl -t snort2c -T show | wc -l | tr -d ' ')"
else
    echo "[!] Table 'snort2c' not found. Ensure Suricata Blocking is enabled on LAN interface."
fi

echo ""
echo "=================================================="
echo " Recent Suricata Drop Events"
echo "=================================================="
if [ -f /var/log/suricata/suricata_em1/alerts.log ]; then
    tail -n 10 /var/log/suricata/suricata_em1/alerts.log
elif [ -f logs/suricata_alerts.log ]; then
    tail -n 10 logs/suricata_alerts.log
else
    echo "[!] Suricata log file not found."
fi

echo ""
echo "=================================================="
echo " pfBlockerNG DNSBL Sinkhole Status"
echo "=================================================="
if [ -f /var/log/pfblockerng/dnsbl.log ]; then
    tail -n 5 /var/log/pfblockerng/dnsbl.log
elif [ -f logs/pfblockerng_dnsbl.log ]; then
    tail -n 5 logs/pfblockerng_dnsbl.log
else
    echo "[!] pfBlockerNG DNSBL log file not found."
fi
