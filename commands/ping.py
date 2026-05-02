"""commands/ping.py – ping command implementation."""

import random
import time


def run_ping(shell, args: list) -> None:
    """Simulate ping: parse -c flag, look up host, print realistic output."""
    if not args:
        print("usage: ping [-c N] <ip>")
        return

    count, targets, i = 4, [], 0
    while i < len(args):
        if args[i] == "-c" and i + 1 < len(args):
            try:
                count = int(args[i + 1])
            except ValueError:
                pass
            i += 2
        else:
            targets.append(args[i])
            i += 1

    if not targets:
        print("usage: ping [-c N] <ip>")
        return

    ip = targets[0]

    if ip not in shell.env.network:
        print(f"ping: {ip}: Name or service not known")
        return

    host    = shell.env.network[ip]
    base_ms = host["latency"]
    name    = host["name"]

    print(f"PING {ip} ({name}) 56(84) bytes of data.")

    rtts = []
    for seq in range(count):
        ms = round(max(0.1, base_ms + random.uniform(-0.3, 0.8)), 3)
        rtts.append(ms)
        print(f"64 bytes from {ip}: icmp_seq={seq} ttl=64 time={ms} ms")
        if seq < count - 1:
            time.sleep(0.05)

    avg  = round(sum(rtts) / len(rtts), 3)
    mdev = round(max(rtts) - min(rtts), 3)
    print(f"\n--- {ip} ping statistics ---")
    print(f"{count} packets transmitted, {count} received, 0% packet loss, time {count * 1000}ms")
    print(f"rtt min/avg/max/mdev = {min(rtts)}/{avg}/{max(rtts)}/{mdev} ms")