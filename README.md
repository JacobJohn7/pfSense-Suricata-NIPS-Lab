# pfSense Firewall & Suricata NIPS Multi-VM Routing Lab

**Author:** Jacob John  
**Gateway:** pfSense 2.7.x Appliance (`192.168.56.254` LAN / `vboxnet0`)  
**Routed Endpoints:** Ubuntu Server (`.106`), Ubuntu Desktop (`.107`), Windows 10 (`.108`)  
**IPS Engine:** Suricata Package on pfSense (Inline NIPS via `netmap` / `pf` `snort2c` table)  

---

### Network Topology & Traffic Routing

I configured a virtual gateway topology in VirtualBox where all inter-VM and outbound traffic from 3 client VMs is forced through pfSense (`192.168.56.254`):

```
                        +----------------------------------------+
                        |  pfSense Firewall / NIPS Appliance     |
                        |  WAN: NAT (DHCP)                       |
                        |  LAN: 192.168.56.254 (Host-Only)       |
                        +----------------------------------------+
                                            |
                 +--------------------------+--------------------------+
                 | (vboxnet0 - 192.168.56.0/24 Default Gateway: .254) |
                 |                                                     |
    +------------+------------+     +-------+---------------+     +----+------------------+
    | Ubuntu Server Target    |     | Ubuntu Desktop (Kali) |     | Windows 10 Workstation |
    | 192.168.56.106          |     | 192.168.56.105        |     | 192.168.56.108         |
    +-------------------------+     +-----------------------+     +------------------------+
```

---

### pfSense Suricata Package Setup & Inline IPS Mode

Suricata was installed via pfSense Package Manager (`Services -> Suricata`) and bound to the LAN interface (`em1`).

Key configuration settings:
- **Block Action:** `Block Path` (Inline IPS mode using BSD `netmap` interface driver).
- **IP Block Table:** `snort2c` (pf kernel table used by pfSense to drop offending IPs instantly).
- **Kill States:** Enabled (drops existing active state table connections upon alert trigger).

**Package override snippet (`config/suricata_pfsense_override.yaml`)**:
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

---

### Custom NIPS Rules (`rules/custom_suricata.rules`)

Added custom signatures to detect and instantly block attack traffic at the firewall layer:

```suricata
# Drop Web Shell / Command Injection Execution
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS HTTP Command Execution Attempt"; flow:established,to_server; content:"cmd.php"; nocase; content:"cmd="; nocase; classtype:web-application-attack; sid:2000001; rev:1;)

# Drop Automated Recon (Nmap User-Agent String)
drop http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PFSENSE-IPS Nmap Scripting Engine Probe Blocked"; flow:established,to_server; content:"Nmap Scripting Engine"; http_user_agent; classtype:attempted-recon; sid:2000002; rev:1;)

# Drop Unauthorized Outbound Reverse Shells
drop tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"PFSENSE-IPS Outbound Unencrypted Reverse Shell Port 4444"; flow:to_server; classtype:trojan-activity; sid:2000003; rev:1;)
```

---

### Attack Verification & Firewall Block Logs

When launching HTTP command injection attempts (`curl http://192.168.56.106/cmd.php?cmd=id`) from `192.168.56.105`, Suricata triggered a `drop` action and immediately inserted `192.168.56.105` into the pf kernel block table (`snort2c`).

#### 1. pfSense Kernel Block Table (`pfctl -t snort2c -T show`)
```text
192.168.56.105
```

#### 2. Suricata Drop Log (`logs/suricata_alerts.log`)
```text
09/17/2026-14:22:05.109283  [Drop] [**] [1:2000001:1] PFSENSE-IPS HTTP Command Execution Attempt [**] {TCP} 192.168.56.105:51240 -> 192.168.56.106:80
09/17/2026-14:25:12.890124  [Drop] [**] [1:2000002:1] PFSENSE-IPS Nmap Scripting Engine Probe Blocked [**] {TCP} 192.168.56.105:51288 -> 192.168.56.106:80
```

#### 3. System Filter Log (`logs/pfsense_filterlog.log`)
```text
Sep 17 14:22:05 pfsense filterlog[82104]: 100,,,1000000103,em1,match,block,in,4,0x0,,64,12934,0,DF,6,tcp,60,192.168.56.105,192.168.56.106,51240,80,0,S
```

---

### Practical Engineering Gotchas & Setup Notes

1. **Netmap Driver Compatibility**: On VirtualBox, selecting **Inline IPS mode** requires emulated NIC type `e1000` (`82540EM`) in VirtualBox settings. Paravirtualized (`virtio-net`) adapters can cause netmap kernel panics during interface initialization on pfSense 2.7.x.
2. **State Table Clearance (`Kill States`)**: If `kill-state: yes` is disabled, active TCP connections established *before* rule evaluation will bypass the block table until the session terminates. Enabling state killing ensures instant session termination upon IPS trigger.
3. **LAN Gateway Assignment**: Updated client `/etc/netplan` (Ubuntu) and Windows IPv4 default gateway properties to point explicitly to `192.168.56.254` so all intra-subnet traffic routes through pfSense interface `em1`.

---

### Repository Structure

- `config/` – Suricata interface override & pfSense block table parameters
- `rules/` – Custom NIPS drop signatures (`custom_suricata.rules`)
- `logs/` – Suricata drop alerts (`suricata_alerts.log`, `eve_drops.json`) and pfSense kernel filter logs (`pfsense_filterlog.log`)
- `scripts/` – Inspection shell script (`verify_blocks.sh`)
