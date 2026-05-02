"""commands/scan.py – scan command implementation."""

import random
import time


def run_scan(shell, args: list) -> None:
    """Simulate nmap-style network scan of the virtual network."""
    show_auth = False
    prefix    = ""
    for a in args:
        if a in ("-A", "--auth"):
            show_auth = True
        elif a.startswith("-"):
            continue
        elif not prefix:
            prefix = a

    print("Starting scan of 192.168.0.0/24")
    print("Host discovery enabled. Scan report:\n")
    time.sleep(0.15)

    found_hosts = {
        ip: info
        for ip, info in shell.env.network.items()
        if not prefix or ip.startswith(prefix)
    }

    if not found_hosts:
        print("Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn")
        print("Nmap done: 0 IP addresses (0 hosts up) scanned")
        return

    for ip, info in sorted(found_hosts.items()):
        latency = round(max(0.1, info["latency"] + random.uniform(-0.2, 0.5)), 2)
        print(f"Nmap scan report for {info['name']} ({ip})")
        print(f"Host is up ({latency}ms latency).")

        services = info.get("services", {})
        if services:
            print(f"{'PORT':<10}  {'STATE':<8}  SERVICE")
            for port, svc in sorted(services.items()):
                print(f"{str(port) + '/tcp':<10}  {'open':<8}  {svc}")

        if info.get("os"):
            print(f"OS: {info['os']}")

        if not info.get("public", True):
            pw = info.get("password", "<unknown>")
            if pw is None:
                auth_descr = "rejects authentication (honeypot)"
            else:
                auth_descr = "password required"
                user = info.get("auth_user")
                if user:
                    auth_descr += f" (user: {user})"
        else:
            auth_descr = "open (no password required)"
        print(f"Auth: {auth_descr}")

        banner = info.get("banner", "")
        if banner:
            print("Banner:")
            for line in banner.splitlines():
                print(f"  {line}")

        print()

    total = len(found_hosts)
    print(f"Nmap done: 254 IP addresses ({total} host{'s' if total != 1 else ''} up) scanned")