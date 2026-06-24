import subprocess
import sys

import streamlit as st

from arp_spoof import ARPSpoofer, SpoofStats

# ----- Page setup -----
st.set_page_config(
    page_title="ARP Spoofing Lab Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# Lab defaults (your VirtualBox host-only network)
DEFAULT_VICTIM = "192.168.56.10"
DEFAULT_SERVER = "192.168.56.30"
DEFAULT_ATTACKER = "192.168.56.20"
DEFAULT_INTERFACE = "eth0"


def get_interfaces() -> list:
    """List network interface names from `ip -br link`."""
    try:
        out = subprocess.check_output(["ip", "-br", "link"], text=True)
        return [line.split()[0] for line in out.strip().splitlines() if line and line.split()[0] != "lo"]
    except Exception:
        return ["eth0", "enp0s3", "enp0s8"]


def is_root() -> bool:
    try:
        import os
        return os.geteuid() == 0
    except AttributeError:
        return False  # Windows host - remind user to run on Kali


# ----- Session state (persists while dashboard is open) -----
if "stats" not in st.session_state:
    st.session_state.stats = SpoofStats()
if "spoofer" not in st.session_state:
    st.session_state.spoofer = ARPSpoofer(st.session_state.stats)

stats: SpoofStats = st.session_state.stats
spoofer: ARPSpoofer = st.session_state.spoofer

# ----- Header -----
st.title("ARP Spoofing Lab Dashboard")
st.caption("Computer Networks project — isolated VirtualBox host-only LAN only")

if not is_root():
    st.error(
        "This dashboard must run as **root** on Kali so Scapy can send ARP packets.\n\n"
        "Stop this app and run:\n"
        "`sudo $(which streamlit) run app.py --server.address 0.0.0.0 --server.port 8501`"
    )

st.warning(
    "**Ethics:** Use only on your own lab VMs (Victim .10, Server .30). "
    "Never run on real college/office Wi-Fi."
)

# ----- Sidebar: configuration -----
with st.sidebar:
    st.header("Attack settings")

    interfaces = get_interfaces()
    default_idx = interfaces.index(DEFAULT_INTERFACE) if DEFAULT_INTERFACE in interfaces else 0
    interface = st.selectbox("Network interface", interfaces, index=default_idx)

    victim_ip = st.text_input("Victim IP", value=DEFAULT_VICTIM)
    server_ip = st.text_input("Server / target IP", value=DEFAULT_SERVER)

    st.info(f"Attacker (this VM): {DEFAULT_ATTACKER}")

    interval = st.slider("ARP packet interval (seconds)", 0.5, 5.0, 2.0, 0.5)
    enable_fwd = st.checkbox("Enable IP forwarding (MITM)", value=True)

    st.divider()
    st.markdown("**How it works**")
    st.markdown(
        "1. Victim thinks Server MAC = Attacker MAC  \n"
        "2. Server thinks Victim MAC = Attacker MAC  \n"
        "3. HTTP traffic flows through Kali  \n"
        "4. Check with Wireshark or `arp -a` on Victim"
    )

# ----- Main layout -----
col_status, col_metrics = st.columns([1, 2])

with col_status:
    st.subheader("Attack status")
    if stats.running:
        st.success("ATTACK RUNNING")
    else:
        st.info("IDLE")

    st.write(f"**Interface:** {stats.interface or interface}")
    st.write(f"**IP forwarding:** {'ON' if stats.ip_forwarding else 'OFF'}")

    if stats.last_error:
        st.error(stats.last_error)

with col_metrics:
    st.subheader("Live metrics")
    m1, m2, m3 = st.columns(3)
    m1.metric("ARP packets sent", stats.packets_sent)
    m2.metric("Victim", stats.victim_ip or victim_ip)
    m3.metric("Server", stats.server_ip or server_ip)

# MAC table when attack has resolved hosts
if stats.attacker_mac or stats.victim_mac or stats.server_mac:
    st.subheader("MAC addresses")
    mac_data = {
        "Role": ["Attacker (Kali)", "Victim", "Server"],
        "IP": [DEFAULT_ATTACKER, stats.victim_ip or victim_ip, stats.server_ip or server_ip],
        "MAC": [
            stats.attacker_mac or "—",
            stats.victim_mac or "—",
            stats.server_mac or "—",
        ],
    }
    st.table(mac_data)

# ----- Control buttons -----
st.subheader("Controls")
btn1, btn2, btn3, btn4 = st.columns(4)

with btn1:
    if st.button("Start ARP spoofing", type="primary", disabled=stats.running):
        ok = spoofer.start(
            interface=interface,
            victim_ip=victim_ip.strip(),
            server_ip=server_ip.strip(),
            interval=interval,
            enable_forwarding=enable_fwd,
        )
        if ok:
            st.toast("Attack started")
        st.rerun()

with btn2:
    if st.button("Stop attack", disabled=not stats.running):
        spoofer.stop(disable_forwarding=False)
        st.toast("Attack stopped")
        st.rerun()

with btn3:
    if st.button("Restore ARP (cleanup)"):
        spoofer.restore_arp(interface, victim_ip.strip(), server_ip.strip())
        st.toast("Restore packets sent")

with btn4:
    if st.button("Clear log"):
        stats.log_lines.clear()
        st.rerun()

# ----- Activity log -----
st.subheader("Activity log")
if stats.log_lines:
    st.code("\n".join(reversed(stats.log_lines)), language="text")
else:
    st.write("No log entries yet. Start the attack to see activity.")

# ----- Demo checklist -----
with st.expander("Demo checklist (for presentation)"):
    st.markdown(
        """
        **Before attack**
        - [ ] All VMs ping each other
        - [ ] Victim opens `http://192.168.56.30`
        - [ ] Victim: `arp -a` shows real server MAC

        **During attack**
        - [ ] Click **Start ARP spoofing** here
        - [ ] Victim: `arp -a | grep 192.168.56.30` shows **Kali MAC**
        - [ ] Wireshark on Kali: filter `http`

        **Defense (static ARP on Victim)**
        - [ ] `sudo arp -s 192.168.56.30 <real_server_mac>`
        - [ ] Start attack again — poisoning should fail

        **After demo**
        - [ ] **Stop attack** → **Restore ARP**
        """
    )

# Auto-refresh metrics while attack runs
if stats.running:
    import time
    time.sleep(1)
    st.rerun()
