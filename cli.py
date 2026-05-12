#!/usr/bin/env python3
"""cli.py – CLI / Jupyter entrypoint for the virtual shell."""
import argparse
import sys
import time

from env import VirtualEnvironment, build_remote_filesystem
from shell import Shell
from completer import ShellCompleter
from utils import decrypt_codename
from commands.connect import run_connect

CURRENT_CODENAME = None
TASK_1_N_PUBLIC  = 5
TASK_1_N_PRIVATE = 2

# ── Shared helpers ─────────────────────────────────────────────────────────────

def _build_env(codename: str, task_level: int | None,
               n_public: int = 5, n_private: int = 2):
    """Build and return (env, shell) for the given task level."""
    if task_level == 1:
        env = VirtualEnvironment(codename, TASK_1_N_PUBLIC, TASK_1_N_PRIVATE)
        env.setup_level1()
        env.update_random_network(num_public=5, num_private=2)
    elif task_level == 2:
        env = VirtualEnvironment(codename, n_public, n_private)
        env.setup_level2()
        env.update_random_network(num_public=305, num_private=5)
    elif task_level == 3:
        env = VirtualEnvironment(codename, n_public, n_private)
        env.setup_level3()
    else:
        env = VirtualEnvironment(codename, n_public, n_private)
        env.build_default_home()
    return env, Shell(env)


def _run_repl(shell, env, *, interactive: bool = True,
              batch_commands: str | None = None,
              silent: bool = False,
              split_semicolons: bool = True) -> None:
    """Run the shell — interactive REPL or non-interactive batch mode.

    interactive=True  → while-True input loop (used by main)
    interactive=False → execute batch_commands then return (used by main batch & solution _step)
    """
    if not interactive:
        raw = (batch_commands or "")
        if split_semicolons:
            raw = raw.replace(";", "\n")
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        for line in lines:
            if not silent:
                path   = shell.get_path(env.cwd)
                prompt = f"{env.user}@{env.hostname}:{path}$ "
                print(prompt + line)
            try:
                shell.run(line)
            except KeyboardInterrupt:
                print("^C")
                env.last_exit_code = 130
            except SystemExit as e:
                print(f"logout (exit code {e.code})")
                break
        return

    # ── Interactive REPL ────────────────────────────────────────────────────
    completer = ShellCompleter(shell, env)
    try:
        import readline as _readline
        _readline.set_completer(completer.readline_match)
        _readline.parse_and_bind("tab: complete")
        _readline.set_completer_delims(" \t\n;|&")
    except (ImportError, AttributeError):
        pass

    print("╔══════════════════════════════════════════════════╗")
    print("║         Cyber Shell Lab  –  Virtual Terminal     ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"   Logged in as  {env.user}@{env.hostname:<20} ")
    print("║  Type  help   to see available commands          ║")
    print("║  Arrow ↑/↓  history  |  Tab  autocomplete        ║")
    print("╚══════════════════════════════════════════════════╝\n")

    try:
        while True:
            path   = shell.get_path(env.cwd)
            prompt = f"{env.user}@{env.hostname}:{path}$ "
            try:
                line = input(prompt)
                while line.endswith("\\"):
                    line = line[:-1]
                    try:
                        line += input("> ")
                    except (EOFError, KeyboardInterrupt):
                        break
            except EOFError:
                print("\nlogout")
                break
            except KeyboardInterrupt:
                print()
                env.last_exit_code = 130
                continue
            if not line:
                continue
            if line.strip() in ("exit", "logout"):
                print("logout")
                break
            try:
                shell.run(line)
            except KeyboardInterrupt:
                print("^C")
                env.last_exit_code = 130
            except SystemExit as e:
                print(f"logout (exit code {e.code})")
                break
    except KeyboardInterrupt:
        print()


# ── Public API ─────────────────────────────────────────────────────────────────

def main(commands=None, codename=None, encrypted_codename=True, task_level=None):
    """Run the virtual shell (interactive or batch)."""
    global CURRENT_CODENAME

    if codename is not None and encrypted_codename:
        codename = decrypt_codename(codename)
    elif codename is None:
        codename = "enigma"

    CURRENT_CODENAME = codename
    n_public, n_private = 5, 2

    if commands is None:
        p = argparse.ArgumentParser(description="Virtual Linux shell lab",
                                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        p.add_argument("--codename", default=codename)
        p.add_argument("--public",   type=int, default=n_public)
        p.add_argument("--private",  type=int, default=n_private)
        p.add_argument("--commands", default=None)
        clean_argv = [a for a in sys.argv[1:]
                      if not a.startswith("-f") and not a.endswith(".json")]
        args      = p.parse_args(clean_argv)
        codename  = args.codename
        n_public  = args.public
        n_private = args.private
        commands  = args.commands

    env, shell = _build_env(codename, task_level, n_public, n_private)
    _run_repl(shell, env,
              interactive=(commands is None),
              batch_commands=commands)


def _step(shell, env, cmd: str, delay: float = 0.4, comment: str = None):
    """Print comment + prompt + command, pause, then execute."""
    if comment:
        for i, ln in enumerate(comment.splitlines()):
            print(f"  {'#' if i == 0 else ' '} {ln}")
        print()
    cmd_lines = cmd.splitlines()
    path   = shell.get_path(env.cwd)
    prompt = f"{env.user}@{env.hostname}:{path}$ "
    print(prompt + cmd_lines[0])
    for ln in cmd_lines[1:]:
        print("> " + ln)
    time.sleep(delay)
    _run_repl(shell, env, interactive=False, batch_commands=cmd,
              silent=True, split_semicolons=False)


def _step_remote(local_env, ip: str, steps: list, delay: float = 0.4):
    """Build a remote shell for the given IP and run (comment, cmd) steps inside it."""
    from commands.connect import run_connect

    host      = local_env.network.get(ip, {})
    name      = host.get("name", ip)
    auth_user = host.get("auth_user", "admin")

    new_env          = VirtualEnvironment()
    new_env.network  = local_env.network
    new_env.hostname = name
    new_env.user     = auth_user
    new_env.vars["HOME"] = f"/home/{auth_user}"
    new_env.vars["USER"] = auth_user
    build_remote_filesystem(
        new_env, host, auth_user,
        codename=host.get("codename", ""),
        is_target=host.get("is_target", False),
    )
    home_node = new_env.root.children.get("home")
    if home_node and auth_user in home_node.children:
        new_env.cwd = home_node.children[auth_user]

    new_shell = Shell(new_env)
    print(f"--- Connected to {name} ({ip}) ---")

    for step_comment, step_cmd in steps:
        if step_comment:
            for i, ln in enumerate(step_comment.splitlines()):
                print(f"  {'#' if i == 0 else ' '} {ln}")
            print()
        path   = new_shell.get_path(new_env.cwd)
        prompt = f"{new_env.user}@{new_env.hostname}:{path}$ "
        for j, ln in enumerate(step_cmd.splitlines()):
            print(prompt + ln if j == 0 else "> " + ln)
        time.sleep(delay)
        _run_repl(new_shell, new_env, interactive=False,
                  batch_commands=step_cmd, silent=True, split_semicolons=False)

    print(f"--- Disconnected from {name} ({ip}) ---\n")


def solution(task_level: int) -> None:
    """Walk through the solution step by step, printing each command as if typed."""
    global CURRENT_CODENAME

    if CURRENT_CODENAME is None:
        CURRENT_CODENAME = "enigma"
        print("  # Note: using default codename 'enigma' — call main() first to set it")

    def _banner(title):
        width = 52
        print("\n" + "╔" + "═" * width + "╗")
        print("║" + f"  {title}".ljust(width) + "║")
        print("╚" + "═" * width + "╝\n")

    if task_level == 1:
        _banner("Level 1 Solution – Step by Step")
        env, shell = _build_env(CURRENT_CODENAME, task_level=1)

        _step(shell, env, "cat readme.md",
              comment="Step 1: read the mission briefing")

        _step(shell, env,
              "nmap 192.168 | awk '/Nmap scan report for/ { ip=$NF; gsub(/[()]/,\"\",ip) }"
              " /Auth: authentication: open/ { print ip }' > ip.txt",
              comment=(
                  "Step 2: scan and save all public IPs to ip.txt.\n"
                  "  On level 1 a student would run nmap first, read the output\n"
                  "  manually, and identify which hosts are open."
              ),
              delay=0.6)

        _step(shell, env, "cat ip.txt",
              comment="Step 3: check which public IPs were found")

        _step(shell, env,
              "while IFS= read -r ip; do; output=$(ssh -q -y \"$ip\" \"cat readme.md\" 2>/dev/null); "
              "if [[ \"$output\" != \"This is not the correct server. Try another host.\" ]]; then; "
              "echo $ip >> correct_ip.txt; break; fi; done < ip.txt",
              comment=(
                  "Step 4: This an automatic way to connect to the server we want to find the codename. "
                  "Normally on this level it is intended to do this manually and not automatically in level 3 the "
                  "goal is to implement that automatically."
              ),
              delay=0.8)

        _step(shell, env, "cat correct_ip.txt",
              comment="Step 5: confirm the correct server IP")

        # Find the target IP from the written file
        correct_ip = None
        try:
            node = shell.env.root
            for part in ["home", env.user, "correct_ip.txt"]:
                node = node.children[part]
            correct_ip = node.content.strip().splitlines()[0].strip()
        except Exception:
            pass

        if correct_ip:
            print("correct_ip:", correct_ip)
            _step_remote(env, correct_ip, [
                ("Step 6: User reads the hint.txt file and knows he needs to locate and go into the folder CodeName.",
                 "cd \"$(find . -type d -name \"CodeName\" | head -n 1)\" "),
                ("Step 7: User sees a readme which tells the file is hidden in this directory and therefore "
                 "can find it via ls -a and read the codename.", "ls -a && cat .codename"),
            ])

        print(f"\n  ✓ Codename: {CURRENT_CODENAME}\n")

    elif task_level == 2:
        _banner("Level 2 Solution – Step by Step")
        print("  (not yet implemented)")

    elif task_level == 3:
        _banner("Level 3 Solution – Step by Step")
        print("  (not yet implemented)")

    else:
        print("No such task level!")
        return

    # Drop into interactive REPL so the student can keep exploring
    # print(" \n\n # Solution complete — shell is yours. Type 'exit' to quit.\n")
    # _run_repl(shell, env, interactive=True)


if __name__ == "__main__":
    #main()
    solution(task_level=1)