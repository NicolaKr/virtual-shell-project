"""commands/connect.py – realistic SSH connection simulation."""

import random
import time

from env import Node, VirtualEnvironment, build_remote_filesystem
from completer import ShellCompleter
from shell import Shell

try:
    import readline as _readline
    _RL_AVAILABLE = True
except ImportError:
    _RL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_fingerprint():
    import hashlib, os
    raw = hashlib.sha256(os.urandom(16)).hexdigest()
    # format as  xx:xx:xx:... (16 pairs)
    return ":".join(raw[i:i+2] for i in range(0, 32, 2))


def _fake_ed25519():
    import hashlib, os, base64
    b = base64.b64encode(os.urandom(32)).decode().rstrip("=")
    return f"SHA256:{b[:43]}"


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def run_connect(shell, args: list, commands: list = None) -> None:
    """Simulate an SSH connection to a virtual host."""
    # Parse: connect [-p port] [-l user] <ip>
    ip        = None
    port      = 22
    req_user  = None
    i = 0
    auto_yes = False
    while i < len(args):
        if args[i] == "-p" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                pass
            i += 2
        elif args[i] == "-l" and i + 1 < len(args):
            req_user = args[i + 1]
            i += 2
        elif args[i] == "-y":
            auto_yes = True
            i += 1
        elif not args[i].startswith("-"):
            ip = args[i]
            i += 1
        else:
            i += 1

    if not ip:
        print("usage: connect [-p port] [-l user] <ip>")
        return

    if ip not in shell.env.network:
        # Simulate connection refused / no route
        time.sleep(random.uniform(0.05, 0.2))
        print(f"ssh: connect to host {ip} port {port}: Connection refused")
        shell.env.last_exit_code = 255
        return

    host      = shell.env.network[ip]
    name      = host["name"]
    ssh_ver   = host.get("ssh_version", "SSH-2.0-OpenSSH_8.9p1")
    auth_user = req_user or host.get("auth_user", "admin")
    correct_pw = host.get("password")   # None = honeypot / no auth
    is_public  = host.get("public", True)

    # --- SSH handshake lines ---
    print(f"SSH client version: OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13 4 Feb 2024")
    time.sleep(0.05)
    print(f"debug1: Connecting to {ip} [{ip}] port {port}.")
    time.sleep(random.uniform(0.05, 0.15))
    print(f"debug1: Connection established.")
    time.sleep(0.04)
    print(f"debug1: identity file /home/student/.ssh/id_ed25519 type -1")
    print(f"debug1: Local version string SSH-2.0-OpenSSH_9.6p1")
    print(f"debug1: Remote protocol version 2.0, remote software version {ssh_ver.replace('SSH-2.0-','')}")
    time.sleep(0.06)
    print(f"debug1: kex: algorithm: curve25519-sha256")
    print(f"debug1: kex: host key algorithm: ecdsa-sha2-nistp256")
    fp = _fake_ed25519()
    print(f"debug1: Server host key: ecdsa-sha2-nistp256 {fp}")

    # First-time host key warning — skipped with -y or when scripted
    if ip not in shell.env.authenticated:
        if auto_yes or commands is not None:
            print(f"Warning: Permanently added '{ip}' (ECDSA) to the list of known hosts.")
        else:
            print(f"The authenticity of host '{ip} ({ip})' can't be established.")
            print(f"ECDSA key fingerprint is {fp}.")
            try:
                ans = input("Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
            except EOFError:
                ans = "yes"
            if ans.strip().lower() not in ("yes", "y", fp):
                print("Host key verification failed.")
                shell.env.last_exit_code = 255
                return
            print(f"Warning: Permanently added '{ip}' (ECDSA) to the list of known hosts.")

    time.sleep(0.05)

    # --- Authentication ---
    authenticated = False

    if is_public:
        print(f"debug1: Authenticating to {ip}:{port} as '{auth_user}'")
        time.sleep(0.04)
        print(f"debug1: Trying private key: /home/student/.ssh/id_ed25519")
        time.sleep(0.06)
        print(f"debug1: Authentication succeeded (publickey).")
        authenticated = True

    elif ip in shell.env.authenticated:
        print(f"debug1: Authenticating to {ip}:{port} as '{auth_user}'")
        time.sleep(0.04)
        print(f"debug1: Trying private key: /home/student/.ssh/id_ed25519")
        time.sleep(0.06)
        print(f"debug1: Authentication succeeded (cached credentials).")
        authenticated = True

    else:
        print(f"debug1: Authenticating to {ip}:{port} as '{auth_user}'")
        time.sleep(0.04)
        print(f"debug1: Trying private key: /home/student/.ssh/id_ed25519")
        time.sleep(0.06)
        print(f"debug1: No such identity: /home/student/.ssh/id_ed25519 (no such file)")
        print(f"debug1: Next authentication method: password")

        for attempt in range(1, 4):
            try:
                entered = input(f"{auth_user}@{ip}'s password: ")
            except EOFError:
                entered = ""

            if correct_pw is None:
                # honeypot
                time.sleep(random.uniform(0.3, 0.6))
                print("Permission denied, please try again.")
                if attempt == 3:
                    print(f"{auth_user}@{ip}: Permission denied (publickey,password).")
                    print(f"ssh: connect to host {ip} port {port}: Too many authentication failures")
                continue

            if entered == correct_pw:
                time.sleep(random.uniform(0.08, 0.15))
                print(f"debug1: Authentication succeeded (password).")
                shell.env.authenticated.add(ip)
                authenticated = True
                break

            time.sleep(random.uniform(0.2, 0.4))
            print("Permission denied, please try again.")

        if not authenticated:
            print(f"{auth_user}@{ip}: Permission denied (publickey,password).")
            shell.env.last_exit_code = 255
            return

    # --- Build remote environment ---
    new_env          = VirtualEnvironment()
    new_env.network  = shell.env.network
    new_env.hostname = name
    new_env.user     = auth_user
    new_env.vars["HOME"] = f"/home/{auth_user}"
    new_env.vars["USER"] = auth_user

    # Populate realistic filesystem
    build_remote_filesystem(
        new_env, host, auth_user,
        codename=host.get("codename", ""),
        is_target=host.get("is_target", False),
    )

    # Set cwd to user home
    home_node = new_env.root.children.get("home")
    if home_node and auth_user in home_node.children:
        new_env.cwd = home_node.children[auth_user]

    new_shell     = Shell(new_env)
    new_completer = ShellCompleter(new_shell, new_env)

    # Save / restore readline completer
    old_completer = None
    if _RL_AVAILABLE:
        try:
            old_completer = _readline.get_completer()
            _readline.set_completer(new_completer.readline_match)
        except Exception:
            pass

    # --- Print MOTD ---
    time.sleep(0.1)
    print()
    banner = host.get("banner", "")
    if banner:
        for line in banner.splitlines():
            print(line)
        print()

    print(f"--- Connected to {name} ({ip}). Type 'exit' or Ctrl+D to disconnect ---")
    print()

    # --- Non-interactive (scripted) mode ---
    if commands is not None:
        for cmd in commands:
            cmd = cmd.strip()
            if not cmd:
                continue
            if cmd in ("exit", "logout"):
                print("logout")
                break
            try:
                new_shell.run(cmd)
            except SystemExit:
                break
        shell.env.last_exit_code = new_env.last_exit_code
        time.sleep(0.04)
        print(f"debug1: client_loop: send disconnect: Disconnected from user {auth_user} {ip} port {port}")
        if _RL_AVAILABLE and old_completer is not None:
            try:
                _readline.set_completer(old_completer)
            except Exception:
                pass
        return

    # --- Interactive REPL ---
    while True:
        try:
            path       = new_shell.get_path(new_env.cwd)
            prompt_str = f"{new_env.user}@{new_env.hostname}:{path}$ "
            line       = input(prompt_str)
        except EOFError:
            print("\nlogout")
            break
        except KeyboardInterrupt:
            print()
            new_env.last_exit_code = 130
            continue

        if line.strip() in ("exit", "logout"):
            print("logout")
            break

        try:
            new_shell.run(line)
        except KeyboardInterrupt:
            print("^C")
            new_env.last_exit_code = 130
        except SystemExit as e:
            print(f"logout (exit code {e.code})")
            break

    # Connection close
    time.sleep(0.04)
    print(f"debug1: client_loop: send disconnect: Disconnected from user {auth_user} {ip} port {port}")

    if _RL_AVAILABLE and old_completer is not None:
        try:
            _readline.set_completer(old_completer)
        except Exception:
            pass

    shell.env.last_exit_code = new_env.last_exit_code

HELP = {
    "ssh": {
        "desc": (
            "Open a secure shell session on a remote host (SSH = Secure SHell).\n"
            "SSH lets you log into another computer over the network and run\n"
            "commands on it as if you were sitting in front of it."
        ),
        "flags": [
            ("-p <port>", "connect on a non-standard port (default is 22)"),
            ("-l <user>", "log in as a different username"),
        ],
        "examples": [
            ("ssh 192.168.0.42",          "connect to a public host (no password)"),
            ("ssh 192.168.0.77",          "connect – will prompt for password if required"),
            ("ssh -l admin 192.168.0.77", "log in as user 'admin'"),
            ("ssh -p 2222 192.168.0.77",  "connect on port 2222 instead of 22"),
        ],
        "tip": (
            "Workflow:\n"
            "  1. Run nmap to find hosts and check which have port 22 open\n"
            "  2. ssh <ip> to connect\n"
            "  3. If asked for a password, check scan output for hints\n"
            "  4. Once inside, explore with ls, cat, find – look for hidden files!\n"
            "  Type 'exit' or Ctrl+D to disconnect and return home."
        ),
    },
}