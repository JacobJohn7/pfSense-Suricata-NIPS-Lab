# pfSense NIPS & Multi-VM Network Security Architecture

---

## Executive Summary

This repository documents the deployment of a **pfSense 2.7.2 enterprise virtual firewall** operating as a centralized gateway and Network Intrusion Prevention System (NIPS) for a segmented virtual laboratory environment (Ubuntu Server target and Ubuntu Desktop client).

By integrating **Suricata** in **Inline IPS mode via BSD `netmap`**, malicious network traffic—including web shell command injection attempts, automated vulnerability scanners, and unauthorized reverse shells—is actively dropped at the network interface layer before reaching target hosts. Offending IP addresses are dynamically injected into the pf kernel state table (`snort2c`) with active TCP session termination (`kill-state`).

---

## Network Topology & Traffic Flow

All inbound, outbound, and inter-subnet traffic from client virtual machines is routed through the pfSense LAN interface (`192.168.56.254`):

```
                        +---------------------------------------+
                        |  pfSense 2.7.2 Firewall & NIPS        |
                        |  WAN: NAT Interface (DHCP)            |
                        |  LAN: 192.168.56.254 (Host-Only em1)  |
                        +---------------------------------------+
                                            |
                    +-----------------------+-----------------------+
                    | (vboxnet0 - 192.168.56.0/24 Default Gateway: .254) |
                    |                                               |
     +--------------+--------------+                +---------------+--------------+
     | Target Node                 |                | Client Node                  |
     | Ubuntu Server               |                | Ubuntu Desktop               |
     | IP: 192.168.56.106          |                | IP: 192.168.56.105           |
     +-----------------------------+                +------------------------------+
```

---

## Suricata Package Setup & Inline NIPS Engine

Suricata is configured on pfSense interface `em1` (`vboxnet0`) using netmap ring buffers for zero-copy packet drop performance.

### Interface Override Config (`config/suricata_pfsense_override.yaml`)

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

---

## Custom NIPS Rule Definitions (`rules/custom_suricata.rules`)

Custom signatures were authored and activated to enforce active packet drops (`drop` action):

```suricata
# 1. Drop Web Shell & Command Execution Attempt
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS HTTP Command Execution Attempt"; flow:established,to_server; content:"cmd.php"; nocase; content:"cmd="; nocase; classtype:web-application-attack; sid:2000001; rev:1;)

# 2. Drop Automated Reconnaissance (Nmap Scripting Engine)
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS Nmap Scripting Engine Probe Blocked"; flow:established,to_server; content:"Nmap Scripting Engine"; http_user_agent; classtype:attempted-recon; sid:2000002; rev:1;)

# 3. Drop Unauthorized Outbound Reverse Shells
drop tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"PFSENSE-IPS Outbound Unencrypted Reverse Shell Port 4444"; flow:to_server; classtype:trojan-activity; sid:2000003; rev:1;)
```

---

## Defense Verification & Real-Time Block Logs

When launching HTTP command injection attempts (`curl http://192.168.56.106/cmd.php?cmd=id`) from `192.168.56.105`, Suricata immediately dropped the packets and populated the kernel table.

### 1. pf Kernel Block Table (`pfctl -t snort2c -T show`)
```text
192.168.56.105
```

### 2. Suricata Fast Alert Log (`logs/suricata_alerts.log`)
```text
09/17/2026-14:22:05.109283  [Drop] [**] [1:2000001:1] PFSENSE-IPS HTTP Command Execution Attempt [**] {TCP} 192.168.56.105:51240 -> 192.168.56.106:80
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
│   └── custom_suricata.rules            # Custom NIPS drop rules (SID 2000001-2000003)
├── logs/
│   ├── suricata_alerts.log              # Suricata text drop log
│   ├── eve_drops.json                   # Structured EVE drop JSON
│   └── pfsense_filterlog.log            # pfSense packet filter log
└── scripts/
    └── verify_blocks.sh                 # pfctl block inspection script
```
