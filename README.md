# pfSense NIPS & Multi-VM Network Security Architecture

![pfSense 2.7.2](https://img.shields.io/badge/pfSense-2.7.2-212529?style=for-the-badge&logo=pfsense&logoColor=white)
![Suricata NIPS](https://img.shields.io/badge/Suricata-Inline_NIPS-red?style=for-the-badge&logo=suricata&logoColor=white)
![BSD netmap](https://img.shields.io/badge/Kernel-BSD_netmap-purple?style=for-the-badge)
![DNSBL](https://img.shields.io/badge/pfBlockerNG-DNSBL_Sinkhole-brightgreen?style=for-the-badge)

---

## Executive Summary

This repository documents the deployment of a **pfSense 2.7.2 enterprise virtual firewall** operating as a centralized gateway, Network Intrusion Prevention System (NIPS), and DNS sinkhole for a segmented virtual laboratory environment (Ubuntu Server target and Ubuntu Desktop client).

By integrating **Suricata** in **Inline IPS mode via BSD `netmap`** alongside **pfBlockerNG-devel**, malicious network traffic—including web shell command injection attempts, automated vulnerability scanners, Log4Shell probes, PAN-OS exploitation attempts, and outbound reverse shells—is actively dropped at the network interface layer. Simultaneously, **pfBlockerNG** handles IP feed blocking (`pfB_PRI1_v4`) and DNSBL domain sinkholing via Unbound DNS resolver integration.

---

## Hard Network Isolation & Routing Architecture

To guarantee 100% gateway inspection, direct NAT access (NIC 1) was **disabled** on both target and client virtual machines. All traffic is physically constrained to Host-Only adapter `vboxnet0` with default gateway set to `192.168.56.254` (pfSense LAN `em1`):

```
                        +---------------------------------------+
                        |  pfSense 2.7.2 Firewall & NIPS        |
                        |  WAN: NAT Interface (DHCP)            |
                        |  LAN: 192.168.56.254 (Host-Only em1)  |
                        |  Packages: Suricata NIPS + pfBlockerNG |
                        +---------------------------------------+
                                            |
                    +-----------------------+-----------------------+
                    | (vboxnet0 - 192.168.56.0/24 Default Gateway: .254) |
                    |                                               |
     +--------------+--------------+                +---------------+--------------+
     | Target Node                 |                | Client Node                  |
     | Ubuntu Server (NAT Disabled)|                | Ubuntu Desktop (NAT Disabled)|
     | IP: 192.168.56.106          |                | IP: 192.168.56.105           |
     | MAC: 08:00:27:B4:AC:8A      |                | MAC: 08:00:27:94:82:86       |
     +-----------------------------+                +------------------------------+
```

---

## Firewall Packages & Security Engine Setup

### 1. Suricata Inline NIPS Engine (`config/suricata_pfsense_override.yaml`)

Configured on pfSense interface `em1` (`vboxnet0`) using BSD `netmap` ring buffers to inspect traffic and dynamically inject dropped IPs into the pf kernel table (`snort2c`):

```yaml
pf:
  block-to-opts: yes
  block-table: snort2c   # Dynamically populate pf kernel table with dropped IPs
  kill-state: yes        # Instantly terminate existing TCP states upon alert match

outputs:
  - fast:
      enabled: yes
      filename: alerts.log
  - eve-log:
      enabled: yes
      types:
        - drop:
            alerts: yes
```

### 2. pfBlockerNG IP & DNSBL Filtering

Configured **pfBlockerNG-devel** with Unbound DNS Resolver integration:
- **IP Blocklists (`IPv4 Feeds`)**: Subscribed to Spamhaus DROP, AbuseIPDB, and PRI1 threat feeds, automatically creating `pfB_PRI1_v4` kernel firewall alias rules.
- **DNSBL Domain Sinkholing**: Intercepts queries to known malicious C2 and phishing domains, returning sinkhole IP (`10.0.0.1`) before requests exit the LAN interface.

---

## Custom NIPS Rule Definitions (`rules/custom_suricata.rules`)

Custom signatures authored and activated to enforce active packet drops (`drop` action):

```suricata
# 1. Drop Web Shell & Command Execution Attempt
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS HTTP Command Execution Attempt"; flow:established,to_server; content:"cmd.php"; nocase; content:"cmd="; nocase; classtype:web-application-attack; sid:2000001; rev:1;)

# 2. Drop Automated Reconnaissance (Nmap Scripting Engine)
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS Nmap Scripting Engine Probe Blocked"; flow:established,to_server; content:"Nmap Scripting Engine"; http_user_agent; classtype:attempted-recon; sid:2000002; rev:1;)

# 3. Drop Unauthorized Outbound Reverse Shells
drop tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"PFSENSE-IPS Outbound Unencrypted Reverse Shell Port 4444"; flow:to_server; classtype:trojan-activity; sid:2000003; rev:1;)

# 4. SSH Brute Force Rate Limiting Threshold
drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"PFSENSE-IPS SSH Brute Force Rate Exceeded"; flow:established,to_server; flags:S; threshold: type threshold, track by_src, count 8, seconds 30; classtype:attempted-admin; sid:2000004; rev:1;)

# 5. Drop Apache Log4j RCE JNDI Ingestion Probe (CVE-2021-44228)
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS Apache Log4j RCE Ingestion Probe (CVE-2021-44228)"; flow:established,to_server; content:"${jndi:"; nocase; fast_pattern; classtype:attempted-admin; reference:cve,2021-44228; sid:2000005; rev:1;)

# 6. Drop PAN-OS GlobalProtect Command Injection Probe (CVE-2024-3400)
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS PAN-OS GlobalProtect SESSID Arbitrary File Creation Probe (CVE-2024-3400)"; flow:established,to_server; content:"/ssl-vpn/hipreport.esp"; http_uri; content:"Cookie|3a|"; nocase; content:"SESSID=../../"; classtype:web-application-attack; reference:cve,2024-3400; sid:2000006; rev:1;)
```

---

## Defense Verification & Real-Time Block Logs

### 1. Suricata Fast Alert Drop Log (`logs/suricata_alerts.log`)
```text
09/17/2026-14:22:05.109283  [Drop] [**] [1:2000001:1] PFSENSE-IPS HTTP Command Execution Attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.56.105:51240 -> 192.168.56.106:80
09/17/2026-14:25:12.890124  [Drop] [**] [1:2000002:1] PFSENSE-IPS Nmap Scripting Engine Probe Blocked [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.56.105:51288 -> 192.168.56.106:80
09/17/2026-14:28:44.204512  [Drop] [**] [1:2000005:1] PFSENSE-IPS Apache Log4j RCE Ingestion Probe (CVE-2021-44228) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 192.168.56.105:51340 -> 192.168.56.106:80
09/17/2026-14:31:44.009182  [Drop] [**] [1:2000003:1] PFSENSE-IPS Outbound Unencrypted Reverse Shell Port 4444 [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 192.168.56.106:49812 -> 192.168.56.105:4444
09/17/2026-14:34:01.884102  [Drop] [**] [1:2000006:1] PFSENSE-IPS PAN-OS GlobalProtect SESSID Arbitrary File Creation Probe (CVE-2024-3400) [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.56.105:51412 -> 192.168.56.106:80
```

### 2. pfBlockerNG DNSBL Sinkhole Log (`logs/pfblockerng_dnsbl.log`)
```text
DNSBL-Block,Sep 17 14:30:12,malicious-c2-domain.test,192.168.56.105,DNSBL_Malware,Block,Unbound-Sinkhole,10.0.0.1
```

### 3. pfSense Kernel Filter Log (`logs/pfsense_filterlog.log`)
```text
Sep 17 14:22:05 pfsense filterlog[82104]: 100,,,1000000103,em1,match,block,in,4,0x0,,64,12934,0,DF,6,tcp,60,192.168.56.105,192.168.56.106,51240,80,0,S
```

---

## Practical Engineering Notes & Troubleshooting

1. **VirtualBox Hardware NIC Driver (`82540EM`)**:
   In VirtualBox VM settings, the network adapter type MUST be configured to **`Intel PRO/1000 MT Desktop (82540EM)`**. Selecting `virtio-net` (paravirtualized) causes netmap kernel panics during interface ring buffer initialization under FreeBSD 14/pfSense 2.7.x.

2. **State Table Clearing (`kill-state`)**:
   Enabling `kill-state: yes` ensures that active TCP connections established prior to rule activation are instantly purged from pfSense's state table when a drop rule fires.

---

## Repository Layout

```
.
├── config/
│   └── suricata_pfsense_override.yaml   # Interface & netmap pf table config
├── rules/
│   └── custom_suricata.rules            # Custom NIPS drop rules (SID 2000001-2000006)
├── logs/
│   ├── suricata_alerts.log              # Suricata text drop log
│   ├── pfblockerng_dnsbl.log            # pfBlockerNG DNSBL sinkhole log
│   ├── eve_drops.jsonl                  # Structured EVE drop NDJSON
│   └── pfsense_filterlog.log            # pfSense packet filter log
└── scripts/
    └── verify_blocks.sh                 # pfctl block & service inspection script
```
