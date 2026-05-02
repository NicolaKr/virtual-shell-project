"""commands/scan.py – realistic nmap-style network scan."""

import random
import time


# Map port → common version strings
_PORT_VERSIONS = {
    22:   ["OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)",
           "OpenSSH 9.2p1 Debian-2 (protocol 2.0)",
           "OpenSSH 9.6p1 (protocol 2.0)",
           "OpenSSH 8.4p1 Debian-5+deb11u3 (protocol 2.0)"],
    21:   ["vsftpd 3.0.5", "ProFTPD 1.3.7c", "Pure-FTPd"],
    80:   ["nginx 1.18.0 (Ubuntu)", "nginx 1.24.0", "Apache httpd 2.4.52 (Ubuntu)",
           "Apache httpd 2.4.53"],
    443:  ["nginx 1.24.0", "Apache httpd 2.4.52"],
    3306: ["MySQL 8.0.35", "MySQL 8.0.32-0ubuntu0.22.04.2", "MariaDB 10.11.2"],
    3389: ["xrdp 0.9.21", "Microsoft Terminal Services"],
}

_SCRIPT_RESULTS = {
    22: [
        ("ssh-hostkey", "2048 SHA256:{} (RSA)\n      256 SHA256:{} (ECDSA)\n      256 SHA256:{} (ED25519)"),
        ("ssh-auth-methods", "  Supported authentication methods: publickey,password"),
    ],
    80: [
        ("http-title", "  Site doesn't have a title (text/html)."),
        ("http-server-header", "  nginx/1.18.0 (Ubuntu)"),
    ],
    21: [
        ("ftp-anon", "  Anonymous FTP login allowed (FTP code 230)"),
        ("ftp-syst", "  STAT:\n  FTP server status:\n   Connected to {ip}\n   No session bandwidth limit"),
    ],
}

_OS_CPE = {
    "Ubuntu 22.04 LTS":  ("Linux 5.15 - 5.19",  "cpe:/o:canonical:ubuntu_linux:22.04"),
    "Ubuntu 24.04 LTS":  ("Linux 6.8",           "cpe:/o:canonical:ubuntu_linux:24.04"),
    "Debian 11":         ("Linux 5.10",           "cpe:/o:debian:debian_linux:11"),
    "Debian 12":         ("Linux 6.1",            "cpe:/o:debian:debian_linux:12"),
    "Linux Mint 21":     ("Linux 5.15",           "cpe:/o:linuxmint:linux_mint:21"),
    "Alpine Linux 3.18": ("Linux 5.15",           "cpe:/o:alpinelinux:alpine_linux:3.18"),
    "Rocky Linux 9":     ("Linux 5.14",           "cpe:/o:rocky:rocky:9"),
    "AlmaLinux 9":       ("Linux 5.14",           "cpe:/o:almalinux:almalinux:9"),
}


def _fake_hash():
    import hashlib, os
    return hashlib.sha256(os.urandom(8)).hexdigest()[:43]


def _mac_for_ip(ip):
    # deterministic-ish but random-looking
    parts = ip.split(".")
    seed  = int(parts[-1]) * 7 + int(parts[-2]) * 13
    random.seed(seed)
    mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
    random.seed()  # restore global random state
    return mac


def run_scan(shell, args: list) -> None:
    show_verbose = False
    prefix       = ""
    scan_type    = "SV"  # default: version scan

    for a in args:
        if a in ("-sV", "-A", "--version"):
            scan_type = "SV"
        elif a in ("-sn", "-sP"):
            scan_type = "ping"
        elif a == "-v":
            show_verbose = True
        elif not a.startswith("-") and not prefix:
            prefix = a

    start_time = time.time()

    print(f"Starting Nmap 7.94 ( https://nmap.org ) at "
          f"{__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M %Z')}")

    if show_verbose:
        print("Initiating ARP Ping Scan at " + __import__('datetime').datetime.now().strftime('%H:%M'))

    # Small realistic delay
    time.sleep(random.uniform(0.1, 0.25))

    found_hosts = {
        ip: info
        for ip, info in shell.env.network.items()
        if not prefix or ip.startswith(prefix)
    }

    if not found_hosts:
        elapsed = round(time.time() - start_time, 2)
        print("Note: Host seems down.")
        print(f"Nmap done: 254 IP addresses (0 hosts up) scanned in {elapsed} seconds")
        return

    for ip, info in sorted(found_hosts.items()):
        latency    = round(max(0.1, info["latency"] + random.uniform(-0.15, 0.4)), 2)
        name       = info["name"]
        os_name    = info.get("os", "Linux")
        services   = info.get("services", {})
        is_public  = info.get("public", True)
        ssh_ver    = info.get("ssh_version", "SSH-2.0-OpenSSH_8.9p1")
        mac        = _mac_for_ip(ip)
        os_info    = _OS_CPE.get(os_name, ("Linux", "cpe:/o:linux:linux_kernel"))

        print(f"\nNmap scan report for {name} ({ip})")
        print(f"Host is up ({latency}ms latency).")

        if not is_public:
            # Show MAC for LAN hosts
            print(f"MAC Address: {mac.upper()} (VMware / QEMU)")

        if scan_type == "ping":
            # ping-only scan, no port details
            continue

        # Port table header
        if services:
            not_shown = random.randint(993, 998) - len(services)
            if not_shown > 0:
                print(f"Not shown: {not_shown} closed tcp ports (reset)")
            print(f"{'PORT':<12}  {'STATE':<8}  {'SERVICE':<12}  VERSION")

            for port, svc in sorted(services.items()):
                versions = _PORT_VERSIONS.get(port, ["unknown"])
                ver_str  = random.choice(versions)
                # Auth-aware state label for private hosts
                state = "open"
                print(f"{str(port) + '/tcp':<12}  {state:<8}  {svc:<12}  {ver_str}")

                # Script output
                if port in _SCRIPT_RESULTS and random.random() < 0.7:
                    script_name, script_tmpl = random.choice(_SCRIPT_RESULTS[port])
                    script_out = script_tmpl.format(
                        _fake_hash(), _fake_hash(), _fake_hash(), ip=ip)
                    print(f"| {script_name}:")
                    for line in script_out.splitlines():
                        print(f"|   {line}")

        # OS detection
        os_guess, cpe = os_info
        confidence    = random.randint(92, 99)
        print(f"OS: {os_name}")
        print(f"OS details: {os_guess}, CPE: {cpe}")
        print(f"OS detection performed. Aggressive OS guesses: {os_name} ({confidence}%)")

        # Network distance
        hops = random.randint(1, 3)
        print(f"Network Distance: {hops} hop{'s' if hops > 1 else ''}")

        # Auth summary line (custom helper info)
        if not is_public:
            auth_user = info.get("auth_user", "admin")
            passwd    = info.get("password")
            if passwd is None:
                auth_line = f"authentication: rejects all (honeypot)"
            else:
                auth_line = f"authentication: password required  (user: {auth_user})"
        else:
            auth_line = "authentication: open (no password)"
        print(f"Auth: {auth_line}")

    elapsed = round(time.time() - start_time, 2)
    total   = len(found_hosts)
    print(f"\nNmap done: 254 IP addresses ({total} host{'s' if total != 1 else ''} up) "
          f"scanned in {elapsed} seconds")
    shell.env.last_exit_code = 0