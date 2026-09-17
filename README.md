# pfSense & Suricata NIPS Lab

Lab configs and custom rules from setting up a pfSense 2.7.2 virtual appliance (`192.168.56.254`) on VirtualBox to act as the default gateway for three client VMs (Ubuntu Server, Ubuntu Desktop, and Windows 10).

Suricata is configured in Inline IPS mode via netmap, pushing blocked IPs directly into pfSense's `snort2c` kernel table.

### Quick Start / Shell Inspection

Inspect active IPS block table on pfSense (via SSH shell or diagnostics):

```bash
pfctl -t snort2c -T show
```

Output when an attacker IP (`192.168.56.105`) triggers a drop rule:
```text
192.168.56.105
```

### Suricata Configuration (`config/suricata_pfsense_override.yaml`)

Interface set to `em1` (LAN / `vboxnet0`). Configured to kill existing TCP connection states upon rule match:

```yaml
pf:
  block-to-opts: yes
  block-table: snort2c
  kill-state: yes

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

### Custom Drop Rules (`rules/custom_suricata.rules`)

```suricata
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS HTTP Command Execution Attempt"; flow:established,to_server; content:"cmd.php"; nocase; content:"cmd="; nocase; classtype:web-application-attack; sid:2000001; rev:1;)
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS Nmap Scripting Engine Probe Blocked"; flow:established,to_server; content:"Nmap Scripting Engine"; http_user_agent; classtype:attempted-recon; sid:2000002; rev:1;)
drop tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"PFSENSE-IPS Outbound Unencrypted Reverse Shell Port 4444"; flow:to_server; classtype:trojan-activity; sid:2000003; rev:1;)
```

### Sample Log Artifacts

`/var/log/suricata/suricata_em1/alerts.log`:
```text
09/17/2026-14:22:05.109283  [Drop] [**] [1:2000001:1] PFSENSE-IPS HTTP Command Execution Attempt [**] {TCP} 192.168.56.105:51240 -> 192.168.56.106:80
```

`/var/log/filter.log` (pfSense packet filter drop entry):
```text
Sep 17 14:22:05 pfsense filterlog[82104]: 100,,,1000000103,em1,match,block,in,4,0x0,,64,12934,0,DF,6,tcp,60,192.168.56.105,192.168.56.106,51240,80,0,S
```

### Notes & Troubleshooting

- **VirtualBox NIC Type:** VirtualBox interface type must be set to `Intel PRO/1000 MT Desktop (82540EM)`. Using `virtio-net` caused FreeBSD netmap panics on interface start.
- **Client Gateways:** Updated `/etc/netplan/50-cloud-init.yaml` on Ubuntu VMs to set gateway `192.168.56.254` so all LAN traffic passes through the pfSense `em1` interface.
