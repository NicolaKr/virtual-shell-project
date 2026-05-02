"""commands/connect.py – connect (simulated SSH) command implementation."""

import time

from env import Node, VirtualEnvironment
from completer import ShellCompleter

try:
    import readline as _readline
    _RL_AVAILABLE = True
except ImportError:
    _RL_AVAILABLE = False


def run_connect(shell, args: list) -> None:
    """Simulate an SSH connection to a virtual host.

    On successful authentication this spawns a nested Shell with a fresh
    VirtualEnvironment representing the remote host. Exiting returns to the
    original shell.
    """
    if not args:
        print("usage: connect <ip>")
        return

    ip = args[0]

    if ip not in shell.env.network:
        print(f"ssh: connect to host {ip} port 22: Connection refused")
        return

    host        = shell.env.network[ip]
    name        = host["name"]
    auth_user   = host.get("auth_user", "admin")
    correct_pw  = host.get("password")   # None = honeypot

    print("SSH client version: OpenSSH_9.6p1")
    print(f"Connecting to {ip} ({name}) port 22...")
    time.sleep(0.1)
    print("Connection established.")
    print("Server SSH version: SSH-2.0-OpenSSH_8.9p1")
    time.sleep(0.05)

    # ---- Authentication ----
    authenticated = False

    if host.get("public", True):
        print("Authenticated (publickey).\n")
        _show_banner(ip, host)
        authenticated = True

    elif ip in shell.env.authenticated:
        print("Authenticated (cached session).\n")
        _show_banner(ip, host)
        authenticated = True

    else:
        print("Authentication required.")
        for attempt in range(1, 4):
            try:
                entered = input(f"{auth_user}@{ip}'s password: ")
            except EOFError:
                entered = ""

            # honeypot – always deny
            if correct_pw is None:
                time.sleep(0.3)
                print("Permission denied, please try again.")
                if attempt == 3:
                    print(f"{auth_user}@{ip}: Permission denied (publickey,password).")
                    print(f"ssh: connect to host {ip}: Too many authentication failures")
                continue

            if entered == correct_pw:
                time.sleep(0.1)
                print("Authenticated.\n")
                shell.env.authenticated.add(ip)
                _show_banner(ip, host)
                authenticated = True
                break

            time.sleep(0.2)
            print("Permission denied, please try again.")

        if not authenticated:
            print(f"\n{auth_user}@{ip}: Permission denied (publickey,password).")
            print(f"ssh: connect to host {ip}: Too many authentication failures")
            return

    # ---- Spawn nested shell ----
    if not authenticated:
        return

    # Import Shell here to avoid a circular import at module level
    from shell import Shell

    new_env          = VirtualEnvironment()
    new_env.network  = shell.env.network
    new_env.hostname = name
    new_env.user     = auth_user
    new_env.vars["HOME"] = f"/home/{auth_user}"

    # Set up the remote home directory
    home_node = new_env.root.children.get("home")
    usr_node  = None
    if home_node is not None:
        home_node.children = {}
        if auth_user and auth_user.lower() == "administrator":
            default_msg = host.get("home_message", "This is not the correct server. Try another host.")
            home_node.children["readme.txt"] = Node("readme.txt", home_node, False, default_msg, owner=auth_user)
        else:
            usr_node = Node(auth_user, home_node, True)
            usr_node.children = {}
            home_node.children[auth_user] = usr_node

    default_msg = host.get("home_message", "This is not the correct server. Try another host.")
    if usr_node is not None:
        usr_node.children["readme.txt"] = Node("readme.txt", usr_node, False, default_msg, owner=auth_user)

    if "flag" in host:
        root_node = new_env.root.children.setdefault("root", Node("root", new_env.root, True))
        if not hasattr(root_node, "children") or root_node.children is None:
            root_node.children = {}
        root_node.children[".flag"] = Node(".flag", root_node, False, host["flag"], owner="root")
        if usr_node is not None:
            usr_node.children["flag.txt"] = Node("flag.txt", usr_node, False, host["flag"], owner=auth_user)

    new_shell     = Shell(new_env)
    new_completer = ShellCompleter(new_shell, new_env)

    old_completer = None
    if _RL_AVAILABLE:
        try:
            old_completer = _readline.get_completer()
            _readline.set_completer(new_completer.readline_match)
        except Exception:
            pass

    print(f"\n--- Connected to {name} ({ip}). Type 'exit' or Ctrl+D to return ---\n")

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

    if _RL_AVAILABLE and old_completer is not None:
        try:
            _readline.set_completer(old_completer)
        except Exception:
            pass


def _show_banner(ip: str, host: dict) -> None:
    """Print the host banner, flag box, and shell hint after a successful login."""
    banner = host.get("banner", "")
    if banner:
        for line in banner.splitlines():
            print(f"  {line}")
        print()

    if "flag" in host:
        print("  ┌──────────────────────────────────────┐")
        print("  │         *** FLAG CAPTURED ***        │")
        print(f"  │  {host['flag']:<36}  │")
        print("  └──────────────────────────────────────┘")
        print()

    hint = host.get("shell_hint", "")
    if hint:
        print(f"  Hint: {hint}\n")