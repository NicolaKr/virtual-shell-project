#!/usr/bin/env python3
"""cli.py – CLI / Jupyter entrypoint for the virtual shell.

Usage (terminal):
    python cli.py [--codename CODE] [--public N] [--private M] [--commands "cmd1 ; cmd2"]

Usage (Jupyter / Python):
    from cli import main
    main(commands="ls ; echo hello ; cat readme")
"""
import argparse
import sys

from env import VirtualEnvironment
from shell import Shell
from completer import ShellCompleter
from utils import decrypt_codename


CURRENT_CODENAME = None

def main(
        commands: str | None = None,
        codename: str | None = None,
        encrypted_codename: bool = True,
        task_level: int | None = None,
) -> None:
    """Run the virtual shell.

    Parameters
    ----------
    commands:
        Optional string of semicolon-separated commands to execute
        non-interactively, then return.  Newlines also work as separators.
    codename:
        Optional codename used for the virtual environment.
    encrypted_codename:
        If True the codename is an encrypted token (from utils.encrypt_codename).
        If False it is used as plain text.
    task_level:
        Optional scenario level used to configure the virtual environment.
    """
    # ── Resolve codename ───────────────────────────────────────────────────
    if codename is not None and encrypted_codename:
        codename = decrypt_codename(codename)   # token → plain word
    elif codename is None:
        codename = "enigma"

    global CURRENT_CODENAME
    CURRENT_CODENAME = codename

    n_public  = 5
    n_private = 2

    # ── Argument parsing (CLI only, skipped when called programmatically) ──
    if commands is None:
        p = argparse.ArgumentParser(
            description="Virtual Linux shell lab",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        p.add_argument("--codename", default=codename,
                       help="codename placed on one public host")
        p.add_argument("--public",   type=int, default=n_public,
                       help="number of public hosts to generate")
        p.add_argument("--private",  type=int, default=n_private,
                       help="number of private hosts to generate")
        p.add_argument("--commands", default=None,
                       help='semicolon-separated commands to run non-interactively')
        # Strip Jupyter kernel flags so argparse doesn't choke
        clean_argv = [a for a in sys.argv[1:]
                      if not a.startswith("-f") and not a.endswith(".json")]
        args = p.parse_args(clean_argv)
        codename  = args.codename
        n_public  = args.public
        n_private = args.private
        commands  = args.commands

    # ── Build environment ──────────────────────────────────────────────────
    env = VirtualEnvironment(codename, n_public, n_private)
    if task_level == 1:
        env.setup_level1()
        env.update_random_network(num_public=5, num_private=2)
    elif task_level == 2:
        env.setup_level2()
        env.update_random_network(num_public=305, num_private=5)
    elif task_level == 3:
        env.setup_level3()
    else:
        env.build_default_home()
    shell = Shell(env)

    # ── Non-interactive batch mode ─────────────────────────────────────────
    if commands is not None:
        lines = [ln.strip() for ln in commands.replace(";", "\n").splitlines()
                 if ln.strip()]
        for line in lines:
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

    # ── Interactive REPL ───────────────────────────────────────────────────
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
                # Backslash line continuation
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


def solution(task_level: int):
    global CURRENT_CODENAME

    if task_level == 1:
        pass
    elif task_level == 2:
        pass
    elif task_level == 3:
        pass
    else:
        print("no such task!")

    print("The codename is:")
    print(CURRENT_CODENAME)




if __name__ == "__main__":
    main()