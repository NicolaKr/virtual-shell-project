"""commands/ping.py – realistic ping simulation."""

import random
import time


def run_ping(shell, args: list) -> None:
    """Simulate ping: parse -c flag, look up host, print realistic output."""
    if not args:
        print("Usage: ping [-c count] [-i interval] [-W timeout] <destination>")
        return

    count = 4
    interval = 1.0
    targets = []
    i = 0
    while i < len(args):
        if args[i] == "-c" and i + 1 < len(args):
            try:
                count = int(args[i + 1])
            except ValueError:
                print(f"ping: invalid count: '{args[i+1]}'")
                return
            i += 2
        elif args[i] == "-i" and i + 1 < len(args):
            try:
                interval = float(args[i + 1])
            except ValueError:
                pass
            i += 2
        elif args[i] == "-W" and i + 1 < len(args):
            i += 2  # ignore timeout for simulation
        elif args[i].startswith("-"):
            i += 1
        else:
            targets.append(args[i])
            i += 1

    if not targets:
        print("ping: usage error: Destination address required")
        return

    ip = targets[0]

    if ip not in shell.env.network:
        # Simulate DNS / host-not-found
        print(f"ping: {ip}: Name or service not known")
        shell.env.last_exit_code = 2
        return

    host    = shell.env.network[ip]
    name    = host["name"]
    base_ms = host["latency"]
    size    = 56  # data bytes

    print(f"PING {ip} ({ip}) {size}({size + 28}) bytes of data.")

    rtts      = []
    received  = 0
    try:
        for seq in range(1, count + 1):
            # Occasional simulated packet loss (~3%)
            if random.random() < 0.03:
                print(f"From {ip} icmp_seq={seq} Destination Host Unreachable")
            else:
                jitter = random.gauss(0, base_ms * 0.08)
                ms = round(max(0.1, base_ms + jitter), 3)
                rtts.append(ms)
                received += 1
                ttl = random.choice([54, 56, 57, 60, 63, 64])
                print(f"{size + 28} bytes from {ip} ({name}): icmp_seq={seq} ttl={ttl} time={ms} ms")

            # respect interval (capped at 0.1 s in simulation)
            if seq < count:
                time.sleep(min(interval, 0.08))
    except KeyboardInterrupt:
        pass

    sent = count
    lost = sent - received
    loss_pct = int(lost / sent * 100) if sent else 100
    total_ms = int(sent * max(interval, 0.001) * 1000)

    print(f"\n--- {ip} ping statistics ---")
    print(f"{sent} packets transmitted, {received} received, {loss_pct}% packet loss, time {total_ms}ms")

    if rtts:
        mn   = round(min(rtts), 3)
        avg  = round(sum(rtts) / len(rtts), 3)
        mx   = round(max(rtts), 3)
        # mdev ≈ mean absolute deviation
        mdev = round(sum(abs(r - avg) for r in rtts) / len(rtts), 3)
        print(f"rtt min/avg/max/mdev = {mn}/{avg}/{mx}/{mdev} ms")

    shell.env.last_exit_code = 0 if received > 0 else 1