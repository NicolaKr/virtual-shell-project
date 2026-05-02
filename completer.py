"""
Shell completer extracted from virtual_shell.py
Provides a readline-compatible tab completer for the virtual shell.
"""

from typing import Optional
try:
    import readline as _readline
except Exception:
    _readline = None


class ShellCompleter:
    """Context-aware tab-completer for readline.

    First token  → complete against command names + aliases.
    Later tokens → complete against virtual filesystem paths.
    """

    def __init__(self, shell: "Shell", env: "VirtualEnvironment") -> None:
        self._shell = shell
        self._env   = env
        self._cache: list = []

    def readline_match(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            try:
                buf = _readline.get_line_buffer()
            except Exception:
                buf = text
            self._cache = self._candidates(buf, text)
        try:
            return self._cache[state]
        except IndexError:
            return None

    def _candidates(self, line_so_far: str, word: str) -> list:
        tokens = line_so_far.lstrip().split()
        completing_cmd = (
            not tokens or
            (len(tokens) == 1 and not line_so_far.endswith(" "))
        )
        if completing_cmd:
            names = sorted(
                list(self._shell.commands.keys()) +
                list(self._shell._aliases.keys())
            )
            return [c for c in names if c.startswith(word)]
        # Path completion
        try:
            if "/" in word:
                dir_part, file_part = word.rsplit("/", 1)
                base   = self._shell.resolve_path(dir_part or "/")
                prefix = dir_part + "/"
            else:
                base      = self._env.cwd
                file_part = word
                prefix    = ""
            if not base.is_dir:
                return []
            return sorted(
                prefix + name + ("/" if node.is_dir else "")
                for name, node in base.children.items()
                if name.startswith(file_part)
            )
        except Exception:
            return []


__all__ = ["ShellCompleter"]
