# ===== immune_system.py =====
"""
ZeroCyber Cross-Platform Immune System
Responsive firewall blocking for Windows (netsh) and Linux (iptables/ufw)
"""

import subprocess
import platform
import os
from typing import Dict, List, Optional
from datetime import datetime


class CrossPlatformImmune:
    """OS-agnostic immune response system."""

    def __init__(self):
        self.os = platform.system().lower()
        self.is_admin = self._check_admin()
        self.blocked_ips = set()

        if self.is_admin:
            print(f"[IMMUNE] {self.os.upper()} immune system initialized (admin mode)")
        else:
            print(f"[IMMUNE] {self.os.upper()} immune system (non-admin, limited functionality)")

    def _check_admin(self) -> bool:
        """Check if running with admin privileges."""
        try:
            if self.os == "windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def block_ip(self, ip: str, duration_minutes: int = 0, reason: str = "") -> bool:
        """Block an IP address at firewall level."""
        if not self.is_admin:
            print(f"[IMMUNE] Admin required to block {ip}")
            return False

        if self.os == "windows":
            return self._block_windows(ip, duration_minutes, reason)
        elif self.os == "linux":
            return self._block_linux(ip, duration_minutes, reason)
        else:
            print(f"[IMMUNE] Unsupported OS: {self.os}")
            return False

    def _block_windows(self, ip: str, duration: int, reason: str) -> bool:
        """Block IP using Windows Firewall (netsh)."""
        try:
            rule_name = f"ZeroCyber-Block-{ip.replace('.', '_')}"

            # Add inbound rule
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=in", "action=block",
                 f"remoteip={ip}", "protocol=any",
                 f"description=ZeroCyber blocked: {reason}"],
                capture_output=True, timeout=10
            )

            # Add outbound rule
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}-out", "dir=out", "action=block",
                 f"remoteip={ip}", "protocol=any"],
                capture_output=True, timeout=10
            )

            self.blocked_ips.add(ip)
            print(f"[IMMUNE] ✓ Blocked {ip} via Windows Firewall")
            return True
        except Exception as e:
            print(f"[IMMUNE] ✗ Failed to block {ip}: {e}")
            return False

    def _block_linux(self, ip: str, duration: int, reason: str) -> bool:
        """Block IP using iptables or ufw."""
        try:
            # Try ufw first (more user-friendly)
            result = subprocess.run(
                ["ufw", "deny", "from", ip],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                print(f"[IMMUNE] ✓ Blocked {ip} via UFW")
                return True

            # Fallback to iptables
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=10
            )
            subprocess.run(
                ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, timeout=10
            )

            self.blocked_ips.add(ip)
            print(f"[IMMUNE] ✓ Blocked {ip} via iptables")
            return True
        except Exception as e:
            print(f"[IMMUNE] ✗ Failed to block {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        if not self.is_admin:
            return False

        if self.os == "windows":
            return self._unblock_windows(ip)
        elif self.os == "linux":
            return self._unblock_linux(ip)
        return False

    def _unblock_windows(self, ip: str) -> bool:
        """Unblock IP on Windows."""
        try:
            rule_name = f"ZeroCyber-Block-{ip.replace('.', '_')}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True, timeout=10
            )
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}-out"],
                capture_output=True, timeout=10
            )
            self.blocked_ips.discard(ip)
            print(f"[IMMUNE] ✓ Unblocked {ip}")
            return True
        except Exception:
            return False

    def _unblock_linux(self, ip: str) -> bool:
        """Unblock IP on Linux."""
        try:
            subprocess.run(
                ["ufw", "delete", "deny", "from", ip],
                capture_output=True, timeout=10
            )
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=10
            )
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, timeout=10
            )
            self.blocked_ips.discard(ip)
            print(f"[IMMUNE] ✓ Unblocked {ip}")
            return True
        except Exception:
            return False

    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IPs."""
        return list(self.blocked_ips)

    def kill_malicious_process(self, pid: int) -> bool:
        """Terminate a suspicious process."""
        if not self.is_admin:
            print(f"[IMMUNE] Admin required to kill process {pid}")
            return False

        try:
            if self.os == "windows":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/F"],
                    capture_output=True, timeout=10
                )
            else:
                subprocess.run(
                    ["kill", "-9", str(pid)],
                    capture_output=True, timeout=10
                )
            print(f"[IMMUNE] ✓ Terminated suspicious process PID {pid}")
            return True
        except Exception as e:
            print(f"[IMMUNE] ✗ Failed to kill PID {pid}: {e}")
            return False

    def quarantine_file(self, file_path: str) -> bool:
        """Move suspicious file to quarantine."""
        try:
            import shutil
            quarantine_dir = "zerocyber_quarantine"
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)

            filename = os.path.basename(file_path)
            dest = os.path.join(quarantine_dir, filename)
            shutil.move(file_path, dest)
            print(f"[IMMUNE] ✓ Quarantined {file_path}")
            return True
        except Exception as e:
            print(f"[IMMUNE] ✗ Failed to quarantine {file_path}: {e}")
            return False

    def get_status(self) -> Dict:
        """Get immune system status."""
        return {
            "os": self.os,
            "admin_mode": self.is_admin,
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ips": list(self.blocked_ips),
            "status": "ACTIVE" if self.is_admin else "LIMITED"
        }
