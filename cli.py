#!/usr/bin/env python3
"""CLI entrypoint for the virtual shell.

Usage: python cli.py --codename CODE --public N --private M
"""
import argparse
from env import VirtualEnvironment
from shell import Shell, ShellCompleter


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--codename", default="enigma", help="codename to place on one public host")
    p.add_argument("--public", type=int, default=3, help="number of public hosts to generate")
    p.add_argument("--private", type=int, default=1, help="number of private hosts to generate")
    args = p.parse_args()

    env = VirtualEnvironment(args.codename, args.public, args.private)
    shell = Shell(env)
    completer = ShellCompleter(shell, env)

    # Setup readline if available (virtual_shell already does this in main), keep minimal here
    try:
        import readline as _readline
        _readline.set_completer(completer.readline_match)
        _readline.parse_and_bind('tab: complete')
    except Exception:
        pass

    # Launch REPL
    try:
        while True:
            path = shell.get_path(env.cwd)
            prompt = f"{env.user}@{env.hostname}:{path}$ "
            try:
                line = input(prompt)
            except EOFError:
                print('\nlogout')
                break
            except KeyboardInterrupt:
                print()
                env.last_exit_code = 130
                continue
            if not line:
                continue
            if line.strip() in ("exit", "logout"):
                print('logout')
                break
            try:
                shell.run(line)
            except SystemExit as e:
                print(f"logout (exit code {e.code})")
                break
    except KeyboardInterrupt:
        print()  


if __name__ == '__main__':
    main()
