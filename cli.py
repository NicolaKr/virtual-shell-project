#!/usr/bin/env python3
"""CLI entrypoint for the virtual shell.

Usage (terminal):
    python cli.py [--codename CODE] [--public N] [--private M] [--commands "cmd1 ; cmd2"]

Usage (Jupyter / Python):
    from cli import main
    main(commands="ls ; echo hello ; cat readme")
"""
import argparse
import base64
import sys
from env import VirtualEnvironment
from shell import Shell
from completer import ShellCompleter

KEY = 120


def _encrypt_codename(plain: str) -> str:
    """Encrypt a plain codename → opaque string safe to embed in a notebook cell.

    Flow:  plain  ──b64encode──▶  bytes  ──XOR──▶  bytes  ──b64encode──▶  str
    The outer b64 makes the result printable / copy-pasteable.
    """
    xored = bytes(b ^ KEY for b in base64.b64encode(plain.encode()))
    return base64.b64encode(xored).decode()


def _decrypt_codename(token: str) -> str:
    """Reverse of _encrypt_codename.  Raises ValueError on bad token."""
    try:
        xored = base64.b64decode(token.encode())
        inner = bytes(b ^ KEY for b in xored)
        return base64.b64decode(inner).decode()
    except Exception as exc:
        raise ValueError(f"Invalid encrypted codename token: {token!r}") from exc


def main(
        commands: str | None = None,
        codename: str | None = None,
        encrypted_codename: bool = True,
        task_level: int | None = None,
):
    """Run the virtual shell.

    Parameters
    ----------
    commands:
        Optional string of semicolon-separated commands to execute
        non-interactively, then return. When provided the REPL is
        skipped. You can also pass multiple lines by using '\n'.

    codename:
        Optional codename used for the virtual environment.

    encrypted_codename:
        If True, the codename is encoded/encrypted before use.
        If False, it is used as plain text.
    task_level:
        Optional task difficulty or scenario level used to configure
        the virtual environment.
    """
    # ── Argument parsing (only when called from the command line) ──────────
    # We reset sys.argv so Jupyter's kernel flags don't confuse argparse.
    # When `commands` is passed programmatically we skip argparse entirely.
    # Allow the codename to be injected via environment variable so a parent
    # process (e.g. a challenge generator) can set it without it being visible
    # in the student's notebook cell.

    # ── Resolve codename ───────────────────────────────────────────────────
    # When called from a notebook the caller passes an encrypted token so the
    # plain word is never visible in the cell.  We decrypt it here.
    # When called from the CLI with --codename the value is already plain text
    # (encrypted_codename=False path).
    if codename is not None and encrypted_codename:
        codename = _decrypt_codename(codename)   # token → plain word
    elif codename is None:
        codename = "enigma"

    n_public  = 5
    n_private = 2

    if commands is None:
        p = argparse.ArgumentParser(
            description="Virtual Linux shell lab",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        p.add_argument("--codename", default=codename,
                       help="codename placed on one public host")
        p.add_argument("--public",   type=int, default=3,
                       help="number of public hosts to generate")
        p.add_argument("--private",  type=int, default=1,
                       help="number of private hosts to generate")
        p.add_argument("--commands", default=None,
                       help='semicolon-separated commands to run non-interactively, '
                            'e.g. --commands "ls ; echo hello"')
        # Strip Jupyter kernel flags so argparse doesn't choke
        clean_argv = [a for a in sys.argv[1:]
                      if not a.startswith("-f") and not a.endswith(".json")]
        args = p.parse_args(clean_argv)
        codename  = args.codename
        n_public  = args.public
        n_private = args.private
        commands  = args.commands   # may still be None → interactive

    # ── Build environment ──────────────────────────────────────────────────
    env   = VirtualEnvironment(codename, n_public, n_private)
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
        # Support both ';' and newline as command separators
        # Split on newlines first, then let shell.run() handle semicolons
        # (which now uses _semicolon_split internally).
        lines = [ln.strip() for ln in commands.replace(";", "\n").splitlines()
                 if ln.strip()]
        for line in lines:
            path   = shell.get_path(env.cwd)
            prompt = f"{env.user}@{env.hostname}:{path}$ "
            print(prompt + line)          # echo the command so output is readable
            try:
                shell.run(line)
            except KeyboardInterrupt:
                print("^C")
                env.last_exit_code = 130
            except SystemExit as e:
                print(f"logout (exit code {e.code})")
                break
        return                            # done — no REPL

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


if __name__ == "__main__":
    main()


# TODO: 1. change command names to real names, update help so that it is adjust to all the tags of the updated version