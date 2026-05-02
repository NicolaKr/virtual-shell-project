"""
shell.py  –  Shell engine for the virtual Linux shell.

Architecture
------------
Node / VirtualEnvironment   → env.py
ScriptInterpreter           → interpreter.py
ShellCompleter              → completer.py
ping / scan / connect       → commands/ping.py, commands/scan.py, commands/connect.py

This module owns:
  Command        – lightweight dataclass describing one built-in command
  Shell          – command dispatcher + all built-in implementations
  main()         – REPL entry point (also importable via cli.py)
"""

import curses
import datetime
import io
import random
import re
import shlex
import sys
import termios
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from env import Node, VirtualEnvironment
from interpreter import ScriptInterpreter
from completer import ShellCompleter

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

def _is_tty() -> bool:
    """Return True only when stdin *and* stdout are a real terminal (TTY)."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


_IN_TTY: bool = _is_tty()

_RL_AVAILABLE = False
try:
    import readline as _readline
    _RL_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Command descriptor
# ---------------------------------------------------------------------------

@dataclass
class Command:
    name:        str
    usage:       str
    description: str
    fn:          Callable


# ---------------------------------------------------------------------------
# Shell engine
# ---------------------------------------------------------------------------

class Shell:
    def __init__(self, env: VirtualEnvironment):
        self.env = env
        self._history: list[str] = []
        self.commands: dict[str, Command] = {}

        for cmd in [
            # filesystem
            Command("ls",        "ls [-la] [path]",             "list directory contents",          self.ls),
            Command("cd",        "cd <path>",                   "change directory",                 self.cd),
            Command("pwd",       "pwd",                         "print working directory",          self.pwd),
            Command("cat",       "cat <file>",                  "print file contents",              self.cat),
            Command("nano",      "nano <file>",                 "edit a file interactively",        self.nano),
            Command("mkdir",     "mkdir [-p] <dir>",            "create a directory",               self.mkdir),
            Command("touch",     "touch <file>",                "create an empty file",             self.touch),
            Command("rm",        "rm [-r] <path>",              "remove file or directory",         self.rm),
            Command("cp",        "cp [-r] <src> <dst>",         "copy a file or directory",         self.cp),
            Command("mv",        "mv <src> <dst>",              "move or rename a file",            self.mv),
            Command("grep",      "grep [-n|-r|-v|-i] <p> <f>",  "search pattern in file",           self.grep),
            Command("find",      "find <path> [-name <pat>]",   "find files by name",               self.find),
            Command("echo",      "echo [-n] <text>",            "print text",                       self.echo),
            Command("printf",    "printf <fmt> [args]",         "formatted print",                  self.printf),
            Command("export",    "export [KEY=val]",            "set or list env variables",        self.export),
            Command("unset",     "unset <var>",                 "unset an env variable",            self.unset),
            Command("chmod",     "chmod <mode> <file>",         "change file permissions",          self.chmod),
            Command("chown",     "chown <owner> <file>",        "change file owner",                self.chown),
            Command("head",      "head [-n N] <file>",          "print first N lines",              self.head),
            Command("tail",      "tail [-n N] <file>",          "print last N lines",               self.tail),
            Command("wc",        "wc [-lwc] <file>",            "word/line/char count",             self.wc),
            Command("sort",      "sort [-r|-n|-u] <file>",      "sort lines of a file",             self.sort),
            Command("uniq",      "uniq [-c] <file>",            "filter/count duplicate lines",     self.uniq),
            Command("cut",       "cut -d <d> -f <n> <file>",   "cut fields from lines",            self.cut),
            Command("tr",        "tr <set1> <set2>",            "translate characters (piped)",     self.tr),
            Command("tee",       "tee <file>",                  "pipe to file and stdout",          self.tee),
            Command("diff",      "diff <file1> <file2>",        "compare two files",                self.diff),
            Command("file",      "file <path>",                 "determine file type",              self.file_cmd),
            Command("stat",      "stat <path>",                 "file status info",                 self.stat),
            Command("du",        "du [-sh] <path>",             "disk usage",                       self.du),
            Command("df",        "df [-h]",                     "disk free space",                  self.df),
            # text / shell utilities
            Command("which",     "which <cmd>",                 "locate a command",                 self.which),
            Command("whoami",    "whoami",                      "print current user",               self.whoami),
            Command("id",        "id",                          "print user/group ids",             self.id_cmd),
            Command("hostname",  "hostname",                    "print hostname",                   self.hostname_cmd),
            Command("uname",     "uname [-a]",                  "system information",               self.uname),
            Command("uptime",    "uptime",                      "system uptime",                    self.uptime_cmd),
            Command("date",      "date",                        "print current date/time",          self.date_cmd),
            Command("history",   "history",                     "show command history",             self.history_cmd),
            Command("read",      "read <var>",                  "read input into variable",         self.read),
            Command("sleep",     "sleep <seconds>",             "sleep for N seconds",              self.sleep_cmd),
            Command("true",      "true",                        "exit with success",                self.true_cmd),
            Command("false",     "false",                       "exit with failure",                self.false_cmd),
            Command("test",      "test <expr>",                 "evaluate expression",              self.test_cmd),
            Command("env",       "env",                         "print all environment variables",  self.env_cmd),
            Command("printenv",  "printenv [VAR]",              "print environment variable",       self.printenv),
            Command("xargs",     "xargs <cmd>",                 "build commands from stdin",        self.xargs),
            # process
            Command("ps",        "ps [-aux]",                   "list processes",                   self.ps),
            Command("kill",      "kill [-9] <pid>",             "send signal to process",           self.kill_cmd),
            Command("jobs",      "jobs",                        "list background jobs",             self.jobs_cmd),
            # network  (thin wrappers that delegate to commands/ modules)
            Command("ping",      "ping [-c N] <ip>",            "check if host is alive",           self.ping),
            Command("scan",      "scan [prefix]",               "scan the network",                 self.scan),
            Command("connect",   "connect <ip>",                "connect to a host",                self.connect),
            Command("ifconfig",  "ifconfig",                    "network interface info",           self.ifconfig),
            Command("ip",        "ip [addr|route]",             "network info (modern)",            self.ip_cmd),
            Command("netstat",   "netstat [-tlnp]",             "network connections",              self.netstat),
            Command("curl",      "curl [-s|-o] <url>",          "transfer data from a URL",         self.curl),
            Command("wget",      "wget <url>",                  "download a file",                  self.wget),
            Command("traceroute","traceroute <ip>",             "trace network path",               self.traceroute),
            Command("nslookup",  "nslookup <host>",             "DNS lookup",                       self.nslookup),
            # scripting / meta
            Command("run",       "run <file.sh>",               "execute a shell script",           self.run_script),
            Command("source",    "source <file>",               "source a script in current shell", self.source_cmd),
            Command("alias",     "alias [name=cmd]",            "define or list aliases",           self.alias_cmd),
            Command("type",      "type <cmd>",                  "describe a command",               self.type_cmd),
            Command("help",      "help [command]",              "show this help",                   self.help),
            Command("man",       "man <command>",               "show manual for a command",        self.man_cmd),
            Command("clear",     "clear",                       "clear screen",                     self.clear),
            Command("exit",      "exit [N]",                    "exit the shell",                   self.exit_cmd),
        ]:
            self.commands[cmd.name] = cmd

        self._aliases: dict[str, str] = {}
        self._ls_capture_mode: bool = False
        self._processes = [
            {"pid": 1,    "user": "root",    "cpu": 0.0, "mem": 0.1, "cmd": "init"},
            {"pid": 423,  "user": "root",    "cpu": 0.0, "mem": 0.3, "cmd": "sshd"},
            {"pid": 512,  "user": "root",    "cpu": 0.0, "mem": 0.2, "cmd": "cron"},
            {"pid": 1001, "user": "student", "cpu": 0.1, "mem": 0.5, "cmd": "bash"},
        ]

    # =========================================================
    # MAIN DISPATCH
    # =========================================================

    def run(self, line: str, _capture: bool = False) -> Optional[str]:
        """Execute one line. Pass _capture=True to return stdout as a string."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        if not self._history or self._history[-1] != line:
            self._history.append(line)

        # Expand aliases
        first_word = line.split()[0]
        if first_word in self._aliases:
            line = self._aliases[first_word] + line[len(first_word):]

        # Pipe:  a | b | c
        if "|" in line and "||" not in line:
            segments = line.split("|")
            output = self._run_single(segments[0].strip(), capture=True) or ""
            for seg in segments[1:-1]:
                buf = io.StringIO()
                old_stdout = sys.stdout
                sys.stdout = buf
                try:
                    self._run_piped(seg.strip(), output)
                finally:
                    sys.stdout = old_stdout
                output = buf.getvalue()
            self._run_piped(segments[-1].strip(), output)
            return None

        # Logical AND
        if "&&" in line:
            for part in line.split("&&"):
                self.run(part.strip())
                if self.env.last_exit_code != 0:
                    break
            return None

        # Logical OR
        if "||" in line:
            parts = line.split("||", 1)
            self.run(parts[0].strip())
            if self.env.last_exit_code != 0:
                self.run(parts[1].strip())
            return None

        # Output redirection
        redir = re.search(r"\s+(2>&1|&>>|&>|>>|2>|>)\s+(\S+)\s*$", line)
        if redir:
            op, dest = redir.group(1), redir.group(2)
            cmd_part = line[:redir.start()]
            output = self._run_single(cmd_part.strip(), capture=True) or ""
            try:
                node = self._get_or_create_file(dest)
                if ">>" in op:
                    node.content += output
                else:
                    node.content = output
                node.touch_mtime()
            except Exception as e:
                print(f"bash: {e}")
            return None

        return self._run_single(line, capture=_capture)

    def _run_single(self, line: str, capture: bool = False) -> Optional[str]:
        """Run a single command with no operators."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        line = self._expand_vars(line)

        # Bare variable assignment: TARGET=192.168.0.1
        if (
            "=" in line
            and not line.startswith("export")
            and not line.startswith("scan")
            and not line.startswith("echo")
            and not line.startswith("printf")
        ):
            key, _, value = line.partition("=")
            if " " not in key.strip() and re.match(r"^[A-Za-z_]\w*$", key.strip()):
                self.env.vars[key.strip()] = value.strip().strip('"\'')
                return None

        if line.startswith("./"):
            return self._dispatch("run", [line[2:]], capture)

        try:
            parts = shlex.split(line)
        except Exception:
            print(f"bash: parse error near '{line}'")
            self.env.last_exit_code = 1
            return None

        if not parts:
            return None

        cmd, args = parts[0], parts[1:]

        if cmd in self.commands:
            if capture:
                buf = io.StringIO()
                old = sys.stdout
                sys.stdout = buf
                if cmd == "ls":
                    self._ls_capture_mode = True
                try:
                    self.commands[cmd].fn(args)
                finally:
                    sys.stdout = old
                    self._ls_capture_mode = False
                return buf.getvalue()
            else:
                self.commands[cmd].fn(args)
        else:
            print(f"bash: command not found: {cmd}")
            self.env.last_exit_code = 127

        return None

    def _dispatch(self, cmd: str, args: list, capture: bool) -> Optional[str]:
        if capture:
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                self.commands[cmd].fn(args)
            finally:
                sys.stdout = old
            return buf.getvalue()
        self.commands[cmd].fn(args)
        return None

    def _run_piped(self, right_cmd: str, stdin_text: str) -> None:
        """Run the right side of a pipe, injecting stdin_text as stdin."""
        right_cmd = self._expand_vars(right_cmd.strip())
        try:
            parts = shlex.split(right_cmd)
        except Exception:
            print("parse error")
            return

        cmd, args = parts[0], parts[1:]

        if cmd == "grep":
            if not args:
                print("grep: missing pattern")
                return
            flags       = [a for a in args if a.startswith("-")]
            targets     = [a for a in args if not a.startswith("-")]
            pattern     = targets[0] if targets else ""
            invert      = "-v" in flags
            insensitive = "-i" in flags
            show_num    = "-n" in flags
            for i, ln in enumerate(stdin_text.splitlines(), 1):
                haystack = ln.lower() if insensitive else ln
                needle   = pattern.lower() if insensitive else pattern
                match    = needle in haystack
                if invert:
                    match = not match
                if match:
                    print(f"{i}:{ln}" if show_num else ln)
        elif cmd == "sort":
            self._pipe_sort(stdin_text, args)
        elif cmd == "uniq":
            self._pipe_uniq(stdin_text, args)
        elif cmd == "wc":
            self._wc_text(stdin_text, args)
        elif cmd == "head":
            n = self._flag_n(args, 10)
            print("\n".join(stdin_text.splitlines()[:n]))
        elif cmd == "tail":
            n = self._flag_n(args, 10)
            print("\n".join(stdin_text.splitlines()[-n:]))
        elif cmd == "tr":
            self._pipe_tr(stdin_text, args)
        elif cmd == "tee":
            if args:
                try:
                    node = self._get_or_create_file(args[0])
                    node.content = stdin_text
                    node.touch_mtime()
                except Exception as e:
                    print(f"tee: {e}")
            print(stdin_text, end="")
        elif cmd == "xargs":
            if args:
                for item in stdin_text.split():
                    self.run(f"{args[0]} {item}")
        elif cmd == "cut":
            self._pipe_cut(stdin_text, args)
        elif cmd == "cat":
            print(stdin_text, end="")
        elif cmd in self.commands:
            self.commands[cmd].fn(args)
        else:
            print(f"bash: command not found: {cmd}")

    # =========================================================
    # PIPE HELPERS
    # =========================================================

    def _pipe_sort(self, text: str, args: list) -> None:
        flags   = "".join(a.lstrip("-") for a in args if a.startswith("-"))
        lines   = text.splitlines()
        reverse = "r" in flags
        numeric = "n" in flags
        unique  = "u" in flags
        key_fn  = (lambda x: int(x) if x.isdigit() else 0) if numeric else str
        if unique:
            seen, deduped = set(), []
            for ln in lines:
                if ln not in seen:
                    seen.add(ln)
                    deduped.append(ln)
            lines = deduped
        lines.sort(key=key_fn, reverse=reverse)
        print("\n".join(lines))

    def _pipe_uniq(self, text: str, args: list) -> None:
        count  = "-c" in args
        lines  = text.splitlines()
        result = []
        i = 0
        while i < len(lines):
            j = i
            while j < len(lines) and lines[j] == lines[i]:
                j += 1
            result.append(f"  {j - i:4}  {lines[i]}" if count else lines[i])
            i = j
        print("\n".join(result))

    def _pipe_tr(self, text: str, args: list) -> None:
        if len(args) < 2:
            print(text, end="")
            return

        def expand_range(s: str) -> str:
            result, i = "", 0
            while i < len(s):
                if i + 2 < len(s) and s[i + 1] == "-":
                    result += "".join(chr(c) for c in range(ord(s[i]), ord(s[i + 2]) + 1))
                    i += 3
                else:
                    result += s[i]
                    i += 1
            return result

        set1 = expand_range(args[0])
        set2 = expand_range(args[1])
        min_len = min(len(set1), len(set2))
        table   = str.maketrans(set1[:min_len], set2[:min_len])
        print(text.translate(table), end="")

    def _pipe_cut(self, text: str, args: list) -> None:
        delim, fields = "\t", []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-d" and i + 1 < len(args):
                delim = args[i + 1]; i += 2
            elif a.startswith("-d") and len(a) > 2:
                delim = a[2:]; i += 1
            elif a == "-f" and i + 1 < len(args):
                try:
                    fields = [int(f) - 1 for f in args[i + 1].split(",")]
                except ValueError:
                    pass
                i += 2
            elif a.startswith("-f") and len(a) > 2:
                try:
                    fields = [int(f) - 1 for f in a[2:].split(",")]
                except ValueError:
                    pass
                i += 1
            else:
                i += 1
        if not text.strip():
            return
        for line in text.splitlines():
            parts    = line.split(delim)
            selected = [parts[f] for f in fields if f < len(parts)]
            print(delim.join(selected))

    # =========================================================
    # VARIABLE EXPANSION (shell level)
    # =========================================================

    def _expand_vars(self, text: str) -> str:
        text = re.sub(r"\$\?", str(self.env.last_exit_code), text)
        text = re.sub(
            r"\$\{(\w+):-([^}]*)\}",
            lambda m: self.env.vars.get(m.group(1), m.group(2)),
            text,
        )
        text = re.sub(
            r"\$\{(\w+)\}",
            lambda m: self.env.vars.get(m.group(1), ""),
            text,
        )
        for k, v in sorted(self.env.vars.items(), key=lambda x: -len(x[0])):
            text = re.sub(rf"\${k}\b", v, text)
        text = re.sub(
            r"\$\(\(\s*(.*?)\s*\)\)",
            lambda m: str(self._eval_arith(m.group(1))),
            text,
        )
        text = re.sub(
            r"\$\(([^)]+)\)",
            lambda m: (self._run_single(m.group(1).strip(), capture=True) or "").strip(),
            text,
        )
        return text

    def _eval_arith(self, expr: str) -> int:
        local = {}
        for k, v in self.env.vars.items():
            try:
                local[k] = int(v)
            except (ValueError, TypeError):
                pass
        try:
            return int(eval(expr, {"__builtins__": {}}, local))
        except Exception:
            return 0

    # =========================================================
    # PATH HELPERS
    # =========================================================

    def resolve_path(self, path: str) -> Node:
        home_path = self.env.vars.get("HOME", "/home/student")

        def _home_node() -> Node:
            parts = home_path.strip("/").split("/")
            node  = self.env.root
            for p in parts:
                if p in getattr(node, "children", {}):
                    node = node.children[p]
                else:
                    break
            return node

        if path.startswith("~/"):
            home_abs = self.get_path(_home_node())
            path = home_abs.rstrip("/") + "/" + path[2:]
        elif path == "~":
            return _home_node()

        if not path or path == ".":
            return self.env.cwd

        node  = self.env.root if path.startswith("/") else self.env.cwd
        parts = path.lstrip("/").split("/") if path.startswith("/") else path.split("/")

        for p in parts:
            if p in ("", "."):
                continue
            if p == "..":
                if node.parent:
                    node = node.parent
                continue
            if not node.is_dir:
                raise FileNotFoundError(f"not a directory: {path}")
            if p not in node.children:
                raise FileNotFoundError(f"no such file or directory: {path}")
            node = node.children[p]

        return node

    def get_path(self, node: Node) -> str:
        parts, cur = [], node
        while cur.parent is not None:
            parts.append(cur.name)
            cur = cur.parent
        return "/" + "/".join(reversed(parts)) if parts else "/"

    def _resolve_dest(self, dest_str: str, src_name: str):
        parent = self.env.cwd
        name   = dest_str
        if "/" in dest_str:
            head, tail = dest_str.rsplit("/", 1)
            parent = self.resolve_path(head)
            name   = tail
        elif dest_str in parent.children and parent.children[dest_str].is_dir:
            parent = parent.children[dest_str]
            name   = src_name
        return parent, name

    def _get_or_create_file(self, path: str) -> Node:
        try:
            return self.resolve_path(path)
        except FileNotFoundError:
            parent = self.env.cwd
            name   = path
            if "/" in path:
                head, name = path.rsplit("/", 1)
                parent = self.resolve_path(head)
            node = Node(name, parent, is_dir=False, content="", owner=self.env.user)
            parent.children[name] = node
            return node

    # =========================================================
    # FILESYSTEM COMMANDS
    # =========================================================

    def ls(self, args: list) -> None:
        flags       = [a for a in args if a.startswith("-")]
        targets     = [a for a in args if not a.startswith("-")]
        long        = any("l" in f for f in flags)
        show_hidden = any("a" in f for f in flags)

        try:
            node = self.resolve_path(targets[0]) if targets else self.env.cwd
        except FileNotFoundError as e:
            print(f"ls: cannot access '{targets[0] if targets else ''}': {e}")
            self.env.last_exit_code = 1
            return

        self.env.last_exit_code = 0

        if not node.is_dir:
            self._ls_long_line(node) if long else print(node.name)
            return

        entries = sorted(node.children.values(), key=lambda n: n.name)
        if not show_hidden:
            entries = [n for n in entries if not n.name.startswith(".")]

        if not entries:
            print("(empty)")
            return

        if long:
            print(f"total {sum(max(1, n.size // 512) for n in entries)}")
            for n in entries:
                self._ls_long_line(n)
        else:
            names = [n.name + ("/" if n.is_dir else "") for n in entries]
            print("\n".join(names) if self._ls_capture_mode else "  ".join(names))

    def _ls_long_line(self, node: Node) -> None:
        kind   = "d" if node.is_dir else "-"
        perms  = kind + node.permissions
        nlinks = len(node.children) + 2 if node.is_dir else 1
        print(f"{perms}  {nlinks:2}  {node.owner:<8} {node.owner:<8} {node.size:6}  {node.mtime_str}  {node.name}")

    def cd(self, args: list) -> None:
        if not args:
            home = self.env.root.children.get("home")
            if home:
                self.env.cwd = home
            return
        try:
            node = self.resolve_path(args[0])
        except FileNotFoundError as e:
            print(f"bash: cd: {e}")
            self.env.last_exit_code = 1
            return
        if not node.is_dir:
            print(f"bash: cd: not a directory: {args[0]}")
            self.env.last_exit_code = 1
            return
        self.env.vars["OLDPWD"] = self.get_path(self.env.cwd)
        self.env.cwd            = node
        self.env.last_exit_code = 0

    def pwd(self, args: list) -> None:
        print(self.get_path(self.env.cwd))
        self.env.last_exit_code = 0

    def cat(self, args: list) -> None:
        if not args:
            print("usage: cat <file>"); return
        for path in args:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError:
                print(f"cat: {path}: No such file or directory")
                self.env.last_exit_code = 1
                continue
            if node.is_dir:
                print(f"cat: {path}: is a directory")
                self.env.last_exit_code = 1
            else:
                print(node.content, end="" if node.content.endswith("\n") else "\n")
                self.env.last_exit_code = 0

    def mkdir(self, args: list) -> None:
        if not args:
            print("usage: mkdir <dir>"); return
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        parents = "-p" in flags

        for path in targets:
            try:
                if parents:
                    self._mkdir_p(path)
                else:
                    parent, name = self.env.cwd, path
                    if "/" in path:
                        head, name = path.rsplit("/", 1)
                        parent = self.resolve_path(head)
                    if name in parent.children:
                        print(f"mkdir: cannot create directory '{path}': File exists")
                        self.env.last_exit_code = 1
                        continue
                    parent.children[name] = Node(name, parent, is_dir=True, owner=self.env.user)
                self.env.last_exit_code = 0
            except FileNotFoundError as e:
                print(f"mkdir: {e}")
                self.env.last_exit_code = 1

    def _mkdir_p(self, path: str) -> None:
        node  = self.env.root if path.startswith("/") else self.env.cwd
        parts = path.lstrip("/").split("/") if path.startswith("/") else path.split("/")
        for p in parts:
            if not p or p == ".":
                continue
            if p == "..":
                if node.parent:
                    node = node.parent
                continue
            if p not in node.children:
                node.children[p] = Node(p, node, is_dir=True, owner=self.env.user)
            node = node.children[p]

    def touch(self, args: list) -> None:
        if not args:
            print("usage: touch <file>"); return
        for path in args:
            try:
                parent, name = self.env.cwd, path
                if "/" in path:
                    head, name = path.rsplit("/", 1)
                    parent = self.resolve_path(head)
                if name not in parent.children:
                    parent.children[name] = Node(name, parent, is_dir=False, content="", owner=self.env.user)
                else:
                    parent.children[name].touch_mtime()
                self.env.last_exit_code = 0
            except FileNotFoundError as e:
                print(f"touch: {e}")
                self.env.last_exit_code = 1

    def rm(self, args: list) -> None:
        if not args:
            print("usage: rm [-r] <path>"); return
        flags     = {a for a in args if a.startswith("-")}
        targets   = [a for a in args if not a.startswith("-")]
        recursive = "-r" in flags or "-rf" in flags or "-fr" in flags
        force     = any("f" in f for f in flags)

        for path in targets:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError:
                if not force:
                    print(f"rm: cannot remove '{path}': No such file or directory")
                    self.env.last_exit_code = 1
                continue
            if node.is_dir and not recursive:
                print(f"rm: cannot remove '{path}': Is a directory")
                self.env.last_exit_code = 1
                continue
            if node.parent is None:
                print("rm: cannot remove root")
                self.env.last_exit_code = 1
                continue
            node.parent.children.pop(node.name)
            self.env.last_exit_code = 0

    def cp(self, args: list) -> None:
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        if len(targets) < 2:
            print("usage: cp [-r] <src> <dst>"); return
        recursive = "-r" in flags or "-R" in flags
        try:
            src = self.resolve_path(targets[0])
        except FileNotFoundError:
            print(f"cp: cannot stat '{targets[0]}': No such file or directory")
            self.env.last_exit_code = 1
            return
        if src.is_dir and not recursive:
            print(f"cp: -r not specified; omitting directory '{targets[0]}'")
            self.env.last_exit_code = 1
            return
        try:
            dest_parent, dest_name = self._resolve_dest(targets[1], src.name)
        except FileNotFoundError as e:
            print(f"cp: {e}")
            self.env.last_exit_code = 1
            return
        self._cp_node(src, dest_parent, dest_name)
        self.env.last_exit_code = 0

    def _cp_node(self, src: Node, dest_parent: Node, dest_name: str) -> None:
        if src.is_dir:
            new_dir = Node(dest_name, dest_parent, is_dir=True, owner=self.env.user)
            dest_parent.children[dest_name] = new_dir
            for child in src.children.values():
                self._cp_node(child, new_dir, child.name)
        else:
            dest_parent.children[dest_name] = Node(
                dest_name, dest_parent, is_dir=False,
                content=src.content, permissions=src.permissions, owner=self.env.user,
            )

    def mv(self, args: list) -> None:
        if len(args) < 2:
            print("usage: mv <src> <dst>"); return
        try:
            src = self.resolve_path(args[0])
        except FileNotFoundError:
            print(f"mv: cannot stat '{args[0]}': No such file or directory")
            self.env.last_exit_code = 1
            return
        try:
            dest_parent, dest_name = self._resolve_dest(args[1], src.name)
        except FileNotFoundError as e:
            print(f"mv: {e}")
            self.env.last_exit_code = 1
            return
        if src.parent:
            src.parent.children.pop(src.name)
        src.name   = dest_name
        src.parent = dest_parent
        dest_parent.children[dest_name] = src
        src.touch_mtime()
        self.env.last_exit_code = 0

    def grep(self, args: list) -> None:
        flags       = [a for a in args if a.startswith("-")]
        targets     = [a for a in args if not a.startswith("-")]
        show_num    = "-n" in flags
        invert      = "-v" in flags
        insensitive = "-i" in flags
        recursive   = "-r" in flags or "-R" in flags
        count_only  = "-c" in flags

        if not targets:
            print("usage: grep [-n|-v|-i|-r|-c] <pattern> <file>")
            self.env.last_exit_code = 1
            return

        pattern = targets[0]
        paths   = targets[1:] if len(targets) > 1 else ["."]
        matches = []

        for path in paths:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError:
                print(f"grep: {path}: No such file or directory"); continue
            if node.is_dir:
                if recursive:
                    matches.extend(self._grep_dir(node, pattern, flags, path))
                else:
                    print(f"grep: {path}: Is a directory")
            else:
                matches.extend(self._grep_file(node, pattern, flags, path if len(paths) > 1 else None))

        if count_only:
            print(len(matches))
        else:
            for m in matches:
                print(m)
        self.env.last_exit_code = 0 if matches else 1

    def _grep_file(self, node: Node, pattern: str, flags: list, label=None) -> list:
        show_num    = "-n" in flags
        invert      = "-v" in flags
        insensitive = "-i" in flags
        results     = []
        for i, ln in enumerate(node.content.splitlines(), 1):
            haystack = ln.lower() if insensitive else ln
            needle   = pattern.lower() if insensitive else pattern
            match    = needle in haystack
            if invert:
                match = not match
            if match:
                prefix = (f"{label}:" if label else "") + (f"{i}:" if show_num else "")
                results.append(prefix + ln)
        return results

    def _grep_dir(self, node: Node, pattern: str, flags: list, prefix: str) -> list:
        results = []
        for child in node.children.values():
            child_path = f"{prefix}/{child.name}"
            if child.is_dir:
                results.extend(self._grep_dir(child, pattern, flags, child_path))
            else:
                results.extend(self._grep_file(child, pattern, flags, child_path))
        return results

    def find(self, args: list) -> None:
        if not args:
            args = ["."]
        path, name_pat, type_pat = args[0], None, None
        i = 1
        while i < len(args):
            if args[i] == "-name" and i + 1 < len(args):
                name_pat = args[i + 1]; i += 2
            elif args[i] == "-type" and i + 1 < len(args):
                type_pat = args[i + 1]; i += 2
            else:
                i += 1
        try:
            start = self.resolve_path(path)
        except FileNotFoundError:
            print(f"find: '{path}': No such file or directory")
            self.env.last_exit_code = 1
            return
        results = []
        self._find_recursive(start, path, name_pat, type_pat, results)
        for r in results:
            print(r)
        self.env.last_exit_code = 0

    def _find_recursive(self, node: Node, path: str, name_pat, type_pat, results: list) -> None:
        def matches(n: Node) -> bool:
            if name_pat:
                pat = re.escape(name_pat).replace(r"\*", ".*").replace(r"\?", ".")
                if not re.fullmatch(pat, n.name):
                    return False
            if type_pat:
                if type_pat == "f" and n.is_dir:  return False
                if type_pat == "d" and not n.is_dir: return False
            return True

        if matches(node):
            results.append(path)
        if node.is_dir:
            for child in node.children.values():
                self._find_recursive(child, f"{path}/{child.name}", name_pat, type_pat, results)

    def echo(self, args: list) -> None:
        no_newline = args and args[0] == "-n"
        if no_newline:
            args = args[1:]
        text = " ".join(args)
        print(text, end="" if no_newline else "\n")
        self.env.last_exit_code = 0

    def printf(self, args: list) -> None:
        if not args:
            print("usage: printf <format> [args]"); return
        fmt, rest = args[0], args[1:]
        try:
            specifiers_per_pass = len(re.findall(r"%[sdif]", fmt))
            passes = (
                [(fmt, [])]
                if specifiers_per_pass == 0 or not rest
                else [(fmt, rest[s:s + specifiers_per_pass]) for s in range(0, max(len(rest), 1), specifiers_per_pass)]
            )
            for cur_fmt, cur_args in passes:
                out, i, arg_i = "", 0, 0
                while i < len(cur_fmt):
                    if cur_fmt[i] == "%" and i + 1 < len(cur_fmt):
                        spec = cur_fmt[i + 1]
                        val  = cur_args[arg_i] if arg_i < len(cur_args) else ""
                        if spec == "s":   out += str(val)
                        elif spec in ("d", "i"): out += str(int(val)) if val else "0"
                        elif spec == "f": out += f"{float(val):.6f}" if val else "0.000000"
                        elif spec == "%": out += "%"
                        elif spec == "n": out += "\n"
                        else:             out += "%" + spec
                        if spec != "%":
                            arg_i += 1
                        i += 2
                    elif cur_fmt[i] == "\\" and i + 1 < len(cur_fmt):
                        esc = cur_fmt[i + 1]
                        out += {"n": "\n", "t": "\t", "\\": "\\"}.get(esc, "\\" + esc)
                        i += 2
                    else:
                        out += cur_fmt[i]; i += 1
                print(out, end="")
        except Exception as e:
            print(f"printf: {e}")
        self.env.last_exit_code = 0

    def export(self, args: list) -> None:
        if not args:
            for k, v in self.env.vars.items():
                print(f'declare -x {k}="{v}"')
            return
        for arg in args:
            if "=" in arg:
                k, _, v = arg.partition("=")
                self.env.vars[k.strip()] = v.strip()
        self.env.last_exit_code = 0

    def unset(self, args: list) -> None:
        for var in args:
            self.env.vars.pop(var, None)
        self.env.last_exit_code = 0

    def read(self, args: list) -> None:
        if not args:
            print("usage: read <var>"); return
        prompt = ""
        var    = args[-1]
        if "-p" in args:
            idx = args.index("-p")
            if idx + 1 < len(args):
                prompt = args[idx + 1]
        try:
            value = input(prompt)
        except EOFError:
            value = ""
        self.env.vars[var] = value
        self.env.last_exit_code = 0

    def sort(self, args: list) -> None:
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: sort [-rnu] <file>"); return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError as e:
            print(f"sort: {e}"); return
        if node.is_dir:
            print("sort: Is a directory"); return
        self._pipe_sort(node.content, flags)

    def uniq(self, args: list) -> None:
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: uniq [-c] <file>"); return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError as e:
            print(f"uniq: {e}"); return
        self._pipe_uniq(node.content, args)

    def cut(self, args: list) -> None:
        targets = [a for a in args if not a.startswith("-") and
                   args[args.index(a) - 1] not in ("-d", "-f")]
        content = ""
        for t in targets:
            try:
                content = self.resolve_path(t).content
            except FileNotFoundError as e:
                print(f"cut: {e}"); return
        self._pipe_cut(content, args)

    def tr(self, args: list) -> None:
        print("usage: echo 'text' | tr <set1> <set2>")

    def tee(self, args: list) -> None:
        print("usage: <cmd> | tee <file>")

    def diff(self, args: list) -> None:
        if len(args) < 2:
            print("usage: diff <file1> <file2>"); return
        try:
            a = self.resolve_path(args[0]).content.splitlines()
            b = self.resolve_path(args[1]).content.splitlines()
        except FileNotFoundError as e:
            print(f"diff: {e}"); return
        i = j = 0
        while i < len(a) or j < len(b):
            if i < len(a) and j < len(b):
                if a[i] == b[j]:
                    i += 1; j += 1
                else:
                    print(f"< {a[i]}"); i += 1
                    print(f"> {b[j]}"); j += 1
            elif i < len(a):
                print(f"< {a[i]}"); i += 1
            else:
                print(f"> {b[j]}"); j += 1
        self.env.last_exit_code = 0

    def file_cmd(self, args: list) -> None:
        if not args:
            print("usage: file <path>"); return
        type_map = {
            "py": "Python script, ASCII text executable",
            "sh": "Bourne-Again shell script, ASCII text executable",
            "md": "Markdown text, ASCII text",
            "txt": "ASCII text",
            "json": "JSON data",
            "html": "HTML document, ASCII text",
        }
        for path in args:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError:
                print(f"file: {path}: No such file or directory"); continue
            if node.is_dir:
                print(f"{path}: directory")
            else:
                ext = path.rsplit(".", 1)[-1] if "." in path else ""
                print(f"{path}: {type_map.get(ext, 'ASCII text')}")

    def stat(self, args: list) -> None:
        if not args:
            print("usage: stat <path>"); return
        try:
            node = self.resolve_path(args[0])
        except FileNotFoundError:
            print(f"stat: cannot stat '{args[0]}': No such file or directory"); return
        kind = "directory" if node.is_dir else "regular file"
        perm = node.permission_bits()
        print(f"  File: {args[0]}")
        print(f"  Size: {node.size}  \tBlocks: {max(1, node.size // 512)}  \tIO Block: 4096  {kind}")
        print(f"Device: sda1  Inode: {abs(hash(node.name)) % 99999}  Links: 1")
        print(f"Access: ({perm:04o}/{'d' if node.is_dir else '-'}{node.permissions})  "
              f"Uid: (1000/{node.owner})  Gid: (1000/{node.owner})")
        print(f"Modify: {node.mtime.strftime('%Y-%m-%d %H:%M:%S.000000000 +0000')}")
        self.env.last_exit_code = 0

    def du(self, args: list) -> None:
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        human   = any("h" in f for f in flags)
        path    = targets[0] if targets else "."
        try:
            node = self.resolve_path(path)
        except FileNotFoundError as e:
            print(f"du: {e}"); return
        total    = self._du_size(node)
        size_str = self._human_size(total) if human else str(max(1, (total + 1023) // 1024))
        print(f"{size_str}\t{path}")

    def _du_size(self, node: Node) -> int:
        if not node.is_dir:
            return node.size
        return sum(self._du_size(c) for c in node.children.values()) + 4096

    def _human_size(self, size: float) -> str:
        for unit in ["B", "K", "M", "G", "T"]:
            if size < 1024:
                return f"{size:.0f}{unit}"
            size /= 1024
        return f"{size:.0f}P"

    def df(self, args: list) -> None:
        human = "-h" in args
        if human:
            print(f"{'Filesystem':<20}  {'Size':>6}  {'Used':>6}  {'Avail':>6}  {'Use%':>5}  Mounted on")
            print(f"{'sda1':<20}  {'20G':>6}  {'4.2G':>6}  {'15G':>6}  {'21%':>5}  /")
            print(f"{'tmpfs':<20}  {'512M':>6}  {'12K':>6}  {'512M':>6}  {'1%':>5}  /tmp")
        else:
            print(f"{'Filesystem':<20}  {'1K-blocks':>10}  {'Used':>10}  {'Available':>10}  {'Use%':>5}  Mounted on")
            print(f"{'sda1':<20}  {20971520:>10}  {4404224:>10}  {15728640:>10}  {'21%':>5}  /")
        print("Just simulation — no real numbers!")

    # =========================================================
    # CHMOD / CHOWN
    # =========================================================

    def chmod(self, args: list) -> None:
        if len(args) < 2:
            print("usage: chmod <mode> <file>"); return
        mode_str, path = args[0], args[1]
        try:
            node = self.resolve_path(path)
        except FileNotFoundError:
            print(f"chmod: cannot access '{path}': No such file or directory"); return

        if re.fullmatch(r"[0-7]{3}", mode_str):
            p = ""
            for digit in mode_str:
                d  = int(digit)
                p += ("r" if d & 4 else "-") + ("w" if d & 2 else "-") + ("x" if d & 1 else "-")
            node.permissions = p
            self.env.last_exit_code = 0
            return

        m = re.fullmatch(r"([ugoa]*)([+\-=])([rwx]+)", mode_str)
        if not m:
            print(f"chmod: invalid mode: {mode_str}"); return

        who, op, perms = m.group(1) or "a", m.group(2), m.group(3)
        if who == "a":
            who = "ugo"

        p        = list(node.permissions)
        who_map  = {"u": (0, 1, 2), "g": (3, 4, 5), "o": (6, 7, 8)}
        perm_map = {"r": 0, "w": 1, "x": 2}

        for w in who:
            offsets = who_map.get(w, ())
            for ch in perms:
                idx = offsets[perm_map[ch]]
                if op == "+":
                    p[idx] = ch
                elif op == "-":
                    p[idx] = "-"
                elif op == "=":
                    for i_ in offsets:
                        p[i_] = "-"
                    p[idx] = ch

        node.permissions    = "".join(p)
        self.env.last_exit_code = 0

    def chown(self, args: list) -> None:
        if len(args) < 2:
            print("usage: chown <owner> <file>"); return
        owner, path = args[0], args[1]
        try:
            node       = self.resolve_path(path)
            node.owner = owner.split(":")[0]
            self.env.last_exit_code = 0
        except FileNotFoundError:
            print(f"chown: cannot access '{path}': No such file or directory")
            self.env.last_exit_code = 1

    # =========================================================
    # HEAD / TAIL / WC helpers
    # =========================================================

    def _flag_n(self, args: list, default: int = 10) -> int:
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args):
                try:
                    return int(args[i + 1])
                except ValueError:
                    pass
            if re.match(r"^-\d+$", a):
                return int(a[1:])
        return default

    def _get_file_args(self, args: list) -> list:
        out, skip = [], False
        for a in args:
            if skip:
                skip = False; continue
            if a == "-n":
                skip = True; continue
            if re.match(r"^-\d+$", a):
                continue
            out.append(a)
        return out

    def head(self, args: list) -> None:
        n       = self._flag_n(args)
        targets = self._get_file_args(args)
        if not targets:
            print("usage: head [-n N] <file>"); return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError:
            print(f"head: cannot open '{targets[0]}': No such file or directory"); return
        if node.is_dir:
            print("head: is a directory"); return
        print("\n".join(node.content.splitlines()[:n]))
        self.env.last_exit_code = 0

    def tail(self, args: list) -> None:
        n       = self._flag_n(args)
        targets = self._get_file_args(args)
        if not targets:
            print("usage: tail [-n N] <file>"); return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError:
            print(f"tail: cannot open '{targets[0]}': No such file or directory"); return
        if node.is_dir:
            print("tail: Is a directory"); return
        print("\n".join(node.content.splitlines()[-n:]))
        self.env.last_exit_code = 0

    def wc(self, args: list) -> None:
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: wc [-lwc] <file>"); return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError:
            print(f"wc: {targets[0]}: No such file or directory"); return
        if node.is_dir:
            print("wc: Is a directory"); return
        self._wc_text(node.content, args, targets[0])
        self.env.last_exit_code = 0

    def _wc_text(self, text: str, flags_args: list, label: str = "") -> None:
        lines  = text.splitlines()
        words  = text.split()
        chars  = len(text)
        flags  = [a for a in flags_args if a.startswith("-")]
        joined = "".join(flags)
        if not flags or not (set(joined) & {"l", "w", "c"}):
            print(f"  {len(lines):4}  {len(words):4}  {chars:4}  {label}")
        else:
            parts = []
            if "l" in joined: parts.append(f"{len(lines):4}")
            if "w" in joined: parts.append(f"{len(words):4}")
            if "c" in joined: parts.append(f"{chars:4}")
            print("  ".join(parts) + (f"  {label}" if label else ""))

    def which(self, args: list) -> None:
        if not args:
            print("usage: which <command>"); return
        for cmd in args:
            if cmd in self.commands:
                print(f"/usr/bin/{cmd}")
            else:
                print(f"which: no {cmd} in ({self.env.vars.get('PATH', '/usr/bin')})")
        self.env.last_exit_code = 0

    # =========================================================
    # SYSTEM INFO COMMANDS
    # =========================================================

    def whoami(self, args: list) -> None:
        print(self.env.user);  self.env.last_exit_code = 0

    def id_cmd(self, args: list) -> None:
        u = self.env.user
        print(f"uid=1000({u}) gid=1000({u}) groups=1000({u}),27(sudo),100(users)")
        self.env.last_exit_code = 0

    def hostname_cmd(self, args: list) -> None:
        print(self.env.hostname);  self.env.last_exit_code = 0

    def uname(self, args: list) -> None:
        if "-a" in args:
            print(f"Linux {self.env.hostname} 5.15.0-91-generic "
                  "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux")
        elif "-r" in args:
            print("5.15.0-91-generic")
        elif "-m" in args:
            print("x86_64")
        else:
            print("Linux")
        self.env.last_exit_code = 0

    def uptime_cmd(self, args: list) -> None:
        print(" 09:45:02 up 2 days,  3:22,  1 user,  load average: 0.15, 0.10, 0.08")
        self.env.last_exit_code = 0

    def date_cmd(self, args: list) -> None:
        print(datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y"))
        self.env.last_exit_code = 0

    def history_cmd(self, args: list) -> None:
        n = int(args[0]) if args and args[0].isdigit() else len(self._history)
        for i, entry in enumerate(self._history[-n:], max(1, len(self._history) - n + 1)):
            print(f"  {i:4}  {entry}")
        self.env.last_exit_code = 0

    def clear(self, args: list) -> None:
        print("\033[2J\033[H", end="")

    def exit_cmd(self, args: list) -> None:
        code = int(args[0]) if args and args[0].isdigit() else 0
        self.env.last_exit_code = code
        raise SystemExit(code)

    def sleep_cmd(self, args: list) -> None:
        if not args:
            print("usage: sleep <seconds>"); return
        try:
            time.sleep(min(float(args[0]), 5))
        except ValueError:
            print(f"sleep: invalid time interval '{args[0]}'")
        self.env.last_exit_code = 0

    def true_cmd(self, args: list) -> None:
        self.env.last_exit_code = 0

    def false_cmd(self, args: list) -> None:
        self.env.last_exit_code = 1

    def test_cmd(self, args: list) -> None:
        si = ScriptInterpreter(self)
        self.env.last_exit_code = 0 if si._eval_test(" ".join(args)) else 1

    def env_cmd(self, args: list) -> None:
        for k, v in sorted(self.env.vars.items()):
            print(f"{k}={v}")
        self.env.last_exit_code = 0

    def printenv(self, args: list) -> None:
        if args:
            for var in args:
                val = self.env.vars.get(var, "")
                if val:
                    print(val)
                else:
                    self.env.last_exit_code = 1
                    return
        else:
            for k, v in sorted(self.env.vars.items()):
                print(f"{k}={v}")
        self.env.last_exit_code = 0

    def xargs(self, args: list) -> None:
        print("usage: <cmd> | xargs <target_cmd>")

    def alias_cmd(self, args: list) -> None:
        if not args:
            for name, val in self._aliases.items():
                print(f"alias {name}='{val}'")
            return
        for arg in args:
            if "=" in arg:
                name, _, cmd = arg.partition("=")
                self._aliases[name] = cmd.strip("'\"")
            elif arg in self._aliases:
                print(f"alias {arg}='{self._aliases[arg]}'")
            else:
                print(f"bash: alias: {arg}: not found")
        self.env.last_exit_code = 0

    def type_cmd(self, args: list) -> None:
        if not args:
            print("usage: type <cmd>"); return
        for cmd in args:
            if cmd in self.commands:
                print(f"{cmd} is a shell builtin")
            elif cmd in self._aliases:
                print(f"{cmd} is aliased to '{self._aliases[cmd]}'")
            else:
                print(f"bash: type: {cmd}: not found")
        self.env.last_exit_code = 0

    # =========================================================
    # PROCESS COMMANDS
    # =========================================================

    def ps(self, args: list) -> None:
        procs    = list(self._processes)
        procs.append({"pid": random.randint(1002, 1100), "user": self.env.user,
                      "cpu": 0.0, "mem": 0.2, "cmd": "ps"})
        show_all = any("a" in a for a in args if a.startswith("-"))
        print(f"{'PID':>7}  {'USER':<10}  {'%CPU':>5}  {'%MEM':>5}  COMMAND")
        for p in procs:
            if not show_all and p["user"] != self.env.user and p["user"] != "root":
                continue
            print(f"{p['pid']:>7}  {p['user']:<10}  {p['cpu']:>5.1f}  {p['mem']:>5.1f}  {p['cmd']}")
        self.env.last_exit_code = 0

    def kill_cmd(self, args: list) -> None:
        if not args:
            print("usage: kill [-9] <pid>"); return
        flags = [a for a in args if a.startswith("-")]
        pids  = [a for a in args if not a.startswith("-")]
        sig   = 9 if "-9" in flags else 15
        for pid_str in pids:
            try:
                pid   = int(pid_str)
                found = [p for p in self._processes if p["pid"] == pid]
                if found:
                    self._processes = [p for p in self._processes if p["pid"] != pid]
                    print(f"Killed process {pid} (SIG{'KILL' if sig == 9 else 'TERM'})")
                else:
                    print(f"bash: kill: ({pid}) - No such process")
                    self.env.last_exit_code = 1
                    return
            except ValueError:
                print(f"kill: invalid pid: {pid_str}")
        self.env.last_exit_code = 0

    def jobs_cmd(self, args: list) -> None:
        print("[1]+  Running    sleep 100 &")
        self.env.last_exit_code = 0

    # =========================================================
    # NANO EDITOR
    # =========================================================

    def nano(self, args: list) -> None:
        """Open the interactive text editor (nano-like).

        Controls
        --------
        Arrow keys          move cursor
        Home / End          start / end of line
        PgUp / PgDn         scroll one screen
        Enter               insert new line
        Backspace / Delete  delete character
        Ctrl+S              save (stay open)
        Ctrl+X              save and quit
        Ctrl+Q              quit (asks if unsaved)
        Ctrl+K              cut current line
        Ctrl+U              paste clipboard
        Ctrl+G              show keybindings
        """
        if not args:
            print("usage: nano <filename>"); return

        filename = args[0]
        parts    = filename.rsplit("/", 1)
        if len(parts) == 2:
            try:
                parent = self.resolve_path(parts[0])
            except FileNotFoundError as e:
                print(e); return
            name = parts[1]
        else:
            parent = self.env.cwd
            name   = parts[0]

        if name in parent.children and not parent.children[name].is_dir:
            lines = parent.children[name].content.splitlines()
        else:
            lines = []
        if not lines:
            lines = [""]

        result_lines = (
            self._nano_curses(filename, lines[:])
            if _IN_TTY
            else self._nano_simple(filename, lines[:])
        )

        if result_lines is None:
            return  # cancelled

        content = "\n".join(result_lines)
        if name in parent.children:
            parent.children[name].content = content
            parent.children[name].touch_mtime()
        else:
            parent.children[name] = Node(name, parent, is_dir=False, content=content, owner=self.env.user)
        print(f'  saved "{filename}" ({len(result_lines)} lines)')
        self.env.last_exit_code = 0

    # ------------------------------------------------------------------
    # Curses (TTY) editor
    # ------------------------------------------------------------------

    def _nano_curses(self, filename: str, lines: list) -> Optional[list]:
        _saved_termios = None
        try:
            fd = sys.stdin.fileno()
            _saved_termios = termios.tcgetattr(fd)
            attrs = termios.tcgetattr(fd)
            attrs[0] &= ~termios.IXON
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except Exception:
            pass

        state: dict = {
            "lines": lines, "cx": 0, "cy": 0, "scroll": 0,
            "modified": False, "saved": False, "cancelled": False,
            "clipboard": "", "msg": "",
        }

        def _editor(stdscr) -> None:
            curses.curs_set(1)
            curses.use_default_colors()
            try:
                curses.start_color()
                curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
                curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
                has_color = True
            except Exception:
                has_color = False

            def clamp():
                state["cy"] = max(0, min(state["cy"], len(state["lines"]) - 1))
                state["cx"] = max(0, min(state["cx"], len(state["lines"][state["cy"]])))
                rows, _ = stdscr.getmaxyx()
                text_rows = max(1, rows - 3)
                if state["cy"] < state["scroll"]:
                    state["scroll"] = state["cy"]
                elif state["cy"] >= state["scroll"] + text_rows:
                    state["scroll"] = state["cy"] - text_rows + 1

            def draw():
                stdscr.erase()
                rows, cols = stdscr.getmaxyx()
                text_rows  = max(1, rows - 3)
                flag  = " [modified]" if state["modified"] else ""
                title = f" nano: {filename}{flag}".ljust(cols - 1)[:cols - 1]
                try:
                    stdscr.addstr(0, 0, title,
                                  curses.color_pair(1) if has_color else curses.A_REVERSE)
                except curses.error:
                    pass
                for row_i in range(text_rows):
                    line_i = state["scroll"] + row_i
                    if line_i >= len(state["lines"]):
                        break
                    try:
                        stdscr.addstr(row_i + 1, 0, state["lines"][line_i][:cols - 1])
                    except curses.error:
                        pass
                help_txt = "  ^S Save  ^X Save+Quit  ^Q Quit  ^K Cut  ^U Paste  ^G Help"
                help_txt = help_txt[:cols - 1].ljust(cols - 1)
                try:
                    stdscr.addstr(rows - 2, 0, help_txt,
                                  curses.color_pair(2) if has_color else curses.A_REVERSE)
                except curses.error:
                    pass
                line_info = f" Ln {state['cy']+1}/{len(state['lines'])}  Col {state['cx']+1}"
                status    = (state["msg"] or line_info)[:cols - 1].ljust(cols - 1)
                try:
                    stdscr.addstr(rows - 1, 0, status)
                except curses.error:
                    pass
                state["msg"] = ""
                vis_cy = state["cy"] - state["scroll"]
                vis_cx = min(state["cx"], cols - 2)
                try:
                    stdscr.move(vis_cy + 1, vis_cx)
                except curses.error:
                    pass
                stdscr.refresh()

            def save():
                state["saved"]    = True
                state["modified"] = False
                state["msg"]      = " File saved."

            while True:
                draw()
                try:
                    key = stdscr.get_wch()
                except curses.error:
                    continue

                rows, cols = stdscr.getmaxyx()
                text_rows  = max(1, rows - 3)
                cur_line   = state["lines"][state["cy"]]

                if key == curses.KEY_UP:
                    if state["cy"] > 0:
                        state["cy"] -= 1
                        state["cx"] = min(state["cx"], len(state["lines"][state["cy"]]))
                    clamp()
                elif key == curses.KEY_DOWN:
                    if state["cy"] < len(state["lines"]) - 1:
                        state["cy"] += 1
                        state["cx"] = min(state["cx"], len(state["lines"][state["cy"]]))
                    clamp()
                elif key == curses.KEY_LEFT:
                    if state["cx"] > 0:
                        state["cx"] -= 1
                    elif state["cy"] > 0:
                        state["cy"] -= 1
                        state["cx"] = len(state["lines"][state["cy"]])
                    clamp()
                elif key == curses.KEY_RIGHT:
                    if state["cx"] < len(cur_line):
                        state["cx"] += 1
                    elif state["cy"] < len(state["lines"]) - 1:
                        state["cy"] += 1
                        state["cx"] = 0
                    clamp()
                elif key in (curses.KEY_HOME, 1):
                    state["cx"] = 0
                elif key in (curses.KEY_END, 5):
                    state["cx"] = len(cur_line)
                elif key == curses.KEY_PPAGE:
                    state["cy"]     = max(0, state["cy"] - text_rows)
                    state["scroll"] = max(0, state["scroll"] - text_rows)
                    clamp()
                elif key == curses.KEY_NPAGE:
                    state["cy"] = min(len(state["lines"]) - 1, state["cy"] + text_rows)
                    clamp()
                elif key in (curses.KEY_BACKSPACE, 127, "\x7f"):
                    if state["cx"] > 0:
                        ln = state["lines"][state["cy"]]
                        state["lines"][state["cy"]] = ln[:state["cx"] - 1] + ln[state["cx"]:]
                        state["cx"] -= 1
                        state["modified"] = True
                    elif state["cy"] > 0:
                        prev = state["lines"][state["cy"] - 1]
                        state["cx"] = len(prev)
                        state["lines"][state["cy"] - 1] = prev + state["lines"][state["cy"]]
                        state["lines"].pop(state["cy"])
                        state["cy"] -= 1
                        state["modified"] = True
                    clamp()
                elif key == curses.KEY_DC:
                    ln = state["lines"][state["cy"]]
                    if state["cx"] < len(ln):
                        state["lines"][state["cy"]] = ln[:state["cx"]] + ln[state["cx"] + 1:]
                        state["modified"] = True
                    elif state["cy"] < len(state["lines"]) - 1:
                        state["lines"][state["cy"]] += state["lines"].pop(state["cy"] + 1)
                        state["modified"] = True
                elif key in ("\n", "\r", curses.KEY_ENTER, 10, 13):
                    ln = state["lines"][state["cy"]]
                    state["lines"][state["cy"]] = ln[:state["cx"]]
                    state["lines"].insert(state["cy"] + 1, ln[state["cx"]:])
                    state["cy"] += 1
                    state["cx"]  = 0
                    state["modified"] = True
                    clamp()
                elif key in ("\x0b", 11):   # Ctrl+K cut
                    state["clipboard"] = state["lines"].pop(state["cy"])
                    if not state["lines"]:
                        state["lines"] = [""]
                    state["cy"] = min(state["cy"], len(state["lines"]) - 1)
                    state["cx"] = min(state["cx"], len(state["lines"][state["cy"]]))
                    state["modified"] = True
                    state["msg"]      = "  Line cut. Press ^U to paste."
                    clamp()
                elif key in ("\x15", 21):   # Ctrl+U paste
                    if state["clipboard"]:
                        state["lines"].insert(state["cy"], state["clipboard"])
                        state["modified"] = True
                        state["msg"]      = "  Pasted."
                    clamp()
                elif key in ("\x13", 19):   # Ctrl+S save
                    save()
                elif key in ("\x18", 24):   # Ctrl+X save+quit
                    state["saved"] = True
                    break
                elif key in ("\x11", 17):   # Ctrl+Q quit
                    if state["modified"] and not state["saved"]:
                        rows2, cols2 = stdscr.getmaxyx()
                        prompt = " Unsaved changes. Save? (y/n): "
                        try:
                            stdscr.addstr(rows2 - 1, 0, prompt.ljust(cols2 - 1))
                            stdscr.refresh()
                            curses.echo()
                            raw = stdscr.getstr(rows2 - 1, len(prompt), 3)
                            curses.noecho()
                            ans = raw.decode("utf-8", errors="ignore").strip().lower()
                        except Exception:
                            ans = "n"
                        if ans in ("y", "yes"):
                            state["saved"] = True
                        else:
                            state["cancelled"] = True
                    break
                elif key in ("\x07", 7):    # Ctrl+G help
                    state["msg"] = "  ^S Save  ^X Save+Quit  ^Q Quit  ^K Cut line  ^U Paste  Arrows Move"
                elif isinstance(key, str) and key.isprintable():
                    ln = state["lines"][state["cy"]]
                    state["lines"][state["cy"]] = ln[:state["cx"]] + key + ln[state["cx"]:]
                    state["cx"] += 1
                    state["modified"] = True
                elif isinstance(key, int) and 32 <= key < 127:
                    ch = chr(key)
                    ln = state["lines"][state["cy"]]
                    state["lines"][state["cy"]] = ln[:state["cx"]] + ch + ln[state["cx"]:]
                    state["cx"] += 1
                    state["modified"] = True

        try:
            curses.wrapper(_editor)
        finally:
            if _saved_termios is not None:
                try:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, _saved_termios)
                except Exception:
                    pass

        return None if state["cancelled"] else state["lines"]

    # ------------------------------------------------------------------
    # Plain line editor (non-TTY fallback)
    # ------------------------------------------------------------------

    def _nano_simple(self, filename: str, lines: list) -> Optional[list]:
        """Simple prompt-based editor for non-TTY environments.

        Commands: :wq  :q!  :s/:list  :a  :d N  :i N <text>  N: <text>
        """
        ext   = filename.rsplit(".", 1)[-1] if "." in filename else ""
        ftype = {"py": "Python", "sh": "Shell", "txt": "Text", "md": "Markdown",
                 "json": "JSON", "js": "JavaScript", "html": "HTML", "css": "CSS"}.get(ext, "File")
        print(f"\n  nano (text mode) — {ftype}: {filename}")
        print("  " + "─" * 53)
        print("  :wq save & quit  |  :q! cancel  |  :s show buffer")
        print("  N: <text>  replace line N  |  :d N  delete line N")
        print("  :a  append mode  |  :i N <text>  insert before N")
        print("  " + "─" * 53 + "\n")

        def show_buf():
            if not lines:
                print("  (empty)")
            else:
                for i, ln in enumerate(lines, 1):
                    print(f"  {i:3} | {ln}")
            print()

        show_buf()
        while True:
            try:
                raw = input("  nano> ")
            except EOFError:
                break
            s = raw.strip()

            if s == ":wq":
                return lines
            if s == ":q!":
                return None
            if s in (":s", ":show", ":l", ":list"):
                show_buf(); continue

            m = re.fullmatch(r":d\s+(\d+)", s)
            if m:
                idx = int(m.group(1)) - 1
                if 0 <= idx < len(lines):
                    print(f"  deleted: {lines.pop(idx)}")
                else:
                    print(f"  error: no line {idx + 1}")
                show_buf(); continue

            m = re.fullmatch(r":i\s+(\d+)\s+(.*)", s, re.DOTALL)
            if m:
                idx = int(m.group(1)) - 1
                lines.insert(max(0, idx), m.group(2))
                print(f"  inserted before line {idx + 1}")
                show_buf(); continue

            if s == ":a":
                print("  append mode – type lines, enter :done to finish\n")
                while True:
                    try:
                        ln = input("  + ")
                    except EOFError:
                        break
                    if ln.strip() == ":done":
                        break
                    lines.append(ln)
                show_buf(); continue

            m = re.fullmatch(r"(\d+):\s*(.*)", s, re.DOTALL)
            if m:
                idx, text = int(m.group(1)) - 1, m.group(2)
                if 0 <= idx < len(lines):
                    lines[idx] = text; print(f"  updated line {idx + 1}")
                elif idx == len(lines):
                    lines.append(text); print(f"  appended line {idx + 1}")
                else:
                    print(f"  error: line {idx + 1} out of range")
                show_buf(); continue

            if raw:
                lines.append(raw)
                print(f"  appended line {len(lines)}")

        return lines

    # =========================================================
    # NETWORK COMMANDS  (delegate to commands/ modules)
    # =========================================================

    def ping(self, args: list) -> None:
        from commands.ping import run_ping
        run_ping(self, args)

    def scan(self, args: list) -> None:
        from commands.scan import run_scan
        run_scan(self, args)

    def connect(self, args: list) -> None:
        from commands.connect import run_connect
        run_connect(self, args)

    def ifconfig(self, args: list) -> None:
        print("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500")
        print("        inet 192.168.0.5  netmask 255.255.255.0  broadcast 192.168.0.255")
        print("        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>")
        print("        ether 00:0c:29:ab:cd:ef  txqueuelen 1000  (Ethernet)")
        print("        RX packets 12345  bytes 8765432 (8.3 MiB)")
        print("        TX packets 9876   bytes 6543210 (6.2 MiB)")
        print()
        print("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536")
        print("        inet 127.0.0.1  netmask 255.0.0.0")
        print("        loop  txqueuelen 1000  (Local Loopback)")
        self.env.last_exit_code = 0

    def ip_cmd(self, args: list) -> None:
        if not args or args[0] in ("addr", "a", "address"):
            print("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN")
            print("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00")
            print("    inet 127.0.0.1/8 scope host lo")
            print("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP")
            print("    link/ether 00:0c:29:ab:cd:ef brd ff:ff:ff:ff:ff:ff")
            print("    inet 192.168.0.5/24 brd 192.168.0.255 scope global eth0")
        elif args[0] in ("route", "r"):
            print("default via 192.168.0.1 dev eth0 proto dhcp metric 100")
            print("192.168.0.0/24 dev eth0 proto kernel scope link src 192.168.0.5")
        else:
            print(f"ip: unknown command '{args[0]}'")
        self.env.last_exit_code = 0

    def netstat(self, args: list) -> None:
        print("Active Internet connections (servers and established)")
        print(f"{'Proto':<6}  {'Local Address':<22}  {'Foreign Address':<22}  State")
        print(f"{'tcp':<6}  {'0.0.0.0:22':<22}  {'0.0.0.0:*':<22}  LISTEN")
        print(f"{'tcp':<6}  {'192.168.0.5:22':<22}  {'192.168.0.1:51234':<22}  ESTABLISHED")
        print(f"{'tcp':<6}  {'127.0.0.1:631':<22}  {'0.0.0.0:*':<22}  LISTEN")
        self.env.last_exit_code = 0

    def curl(self, args: list) -> None:
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: curl [-s|-o <file>] <url>"); return

        url = targets[0]
        responses = {
            "http://192.168.0.10":  (
                "<!DOCTYPE html>\n<html>\n<head><title>Cyber Lab Web Server</title></head>\n"
                "<body><h1>Welcome to the Cyber Lab</h1><p>Nothing to see here...</p></body>\n</html>"
            ),
            "http://192.168.0.10/": (
                "<!DOCTYPE html>\n<html>\n<head><title>Cyber Lab Web Server</title></head>\n"
                "<body><h1>Welcome to the Cyber Lab</h1><p>Nothing to see here...</p></body>\n</html>"
            ),
            "http://192.168.0.50:8080": '{"status":"ok","message":"Admin panel running","version":"1.2.3"}',
        }
        content = responses.get(
            url, f"curl: (6) Could not resolve host: {url.split('/')[2] if '//' in url else url}"
        )
        silent = "-s" in flags

        if "-o" in args:
            for i, a in enumerate(args):
                if a == "-o" and i + 1 < len(args):
                    out_file = args[i + 1]
                    try:
                        node = self._get_or_create_file(out_file)
                        node.content = content
                        if not silent:
                            print("  % Total    % Received % Xferd")
                            print(f"100   {len(content)}  100   {len(content)}    0     0  12345"
                                  "      0 --:--:-- --:--:-- --:--:-- 12345")
                    except Exception as e:
                        print(f"curl: {e}")
                    return

        print(content)
        self.env.last_exit_code = 0 if "curl: " not in content else 6

    def wget(self, args: list) -> None:
        if not args:
            print("usage: wget <url>"); return
        url      = args[0]
        filename = url.split("/")[-1] or "index.html"
        print(f"--2025-04-10 09:45:01--  {url}")
        print(f"Connecting to {url.split('/')[2] if '//' in url else url}... connected.")
        time.sleep(0.1)
        if "192.168.0.10" in url:
            content = "<html><body>Cyber Lab</body></html>"
            node    = self._get_or_create_file(filename)
            node.content = content
            print("HTTP request sent, awaiting response... 200 OK")
            print(f"Length: {len(content)} [text/html]")
            print(f"Saving to: '{filename}'")
            print(f"'{filename}' saved [{len(content)}/{len(content)}]")
            self.env.last_exit_code = 0
        else:
            print("HTTP request sent, awaiting response... 404 Not Found")
            print("wget: server returned error: HTTP/1.1 404 Not Found")
            self.env.last_exit_code = 8

    def traceroute(self, args: list) -> None:
        if not args:
            print("usage: traceroute <ip>"); return
        ip = args[0]
        print(f"traceroute to {ip}, 30 hops max, 60 byte packets")
        hops = [("192.168.0.254", "gateway"), ("10.0.0.1", "isp-edge")]
        if ip in self.env.network:
            hops.append((ip, self.env.network[ip]["name"]))
        for i, (hop_ip, hop_name) in enumerate(hops, 1):
            base = random.uniform(1, 15)
            ms1  = round(base, 3)
            ms2  = round(base + random.uniform(0, 1), 3)
            ms3  = round(base + random.uniform(0, 2), 3)
            print(f" {i:2}  {hop_name} ({hop_ip})  {ms1} ms  {ms2} ms  {ms3} ms")
        self.env.last_exit_code = 0

    def nslookup(self, args: list) -> None:
        if not args:
            print("usage: nslookup <host>"); return
        host       = args[0]
        hosts_node = (
            self.env.root.children.get("etc", Node("etc", self.env.root))
                         .children.get("hosts")
        )
        print("Server:\t\t127.0.0.53")
        print("Address:\t127.0.0.53#53\n")
        if hosts_node:
            for line in hosts_node.content.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == host:
                    print("Non-authoritative answer:")
                    print(f"Name:\t{host}")
                    print(f"Address: {parts[0]}")
                    self.env.last_exit_code = 0
                    return
        print(f"** server can't find {host}: NXDOMAIN")
        self.env.last_exit_code = 1

    # =========================================================
    # SCRIPT ENGINE
    # =========================================================

    def run_script(self, args: list) -> None:
        if not args:
            print("usage: run <file.sh>"); return
        script_path, script_args = args[0], args[1:]
        try:
            node = self.resolve_path(script_path)
        except FileNotFoundError:
            print(f"bash: {script_path}: No such file or directory")
            self.env.last_exit_code = 127
            return
        if node.is_dir:
            print(f"bash: {script_path}: Is a directory")
            self.env.last_exit_code = 126
            return
        if "x" not in node.permissions[:3]:
            print(f"bash: {script_path}: Permission denied")
            print(f"  (hint: chmod +x {script_path})")
            self.env.last_exit_code = 126
            return

        extra = {
            "0": script_path, "@": " ".join(script_args),
            "#": str(len(script_args)), "*": " ".join(script_args),
            **{str(i): a for i, a in enumerate(script_args, 1)},
        }
        lines = node.content.splitlines()
        if lines and lines[0].startswith("#!"):
            lines = lines[1:]
        ScriptInterpreter(self).run_lines(lines, extra_vars=extra)

    def source_cmd(self, args: list) -> None:
        if not args:
            print("usage: source <file>"); return
        try:
            node = self.resolve_path(args[0])
        except FileNotFoundError:
            print(f"bash: {args[0]}: No such file or directory")
            self.env.last_exit_code = 1
            return
        lines = node.content.splitlines()
        if lines and lines[0].startswith("#!"):
            lines = lines[1:]
        ScriptInterpreter(self).run_lines(lines)

    # =========================================================
    # HELP / MAN
    # =========================================================

    HELP_DETAIL = {
        "ls": {
            "desc": "List directory contents.",
            "flags": [
                ("-l",  "long format: permissions, owner, size, mtime"),
                ("-a",  "show hidden files (names starting with .)"),
                ("-la", "combine long format and hidden files"),
            ],
            "examples": [
                ("ls",          "list current directory"),
                ("ls -l",       "long listing with permissions and sizes"),
                ("ls -la /etc", "long + hidden files in /etc"),
            ],
            "tip": "Directories are shown with a trailing /.  Use 'cd <dir>' to enter one.",
        },
        "cd": {
            "desc": "Change the current working directory.",
            "flags": [],
            "examples": [
                ("cd /etc", "go to /etc"),
                ("cd ..",   "go up one level"),
                ("cd ~",    "go to home directory"),
                ("cd -",    "go to previous directory (uses $OLDPWD)"),
            ],
            "tip": "After cd, run 'pwd' to confirm your new location.",
        },
        "cat": {
            "desc": "Print the contents of one or more files to the screen.",
            "flags": [],
            "examples": [
                ("cat file.txt",           "print file.txt"),
                ("cat /etc/passwd",        "print the system password file"),
                ("cat file1.txt file2.txt","print two files one after the other"),
            ],
            "tip": "For long files use 'head', 'tail', or pipe through 'less'.",
        },
        "echo": {
            "desc": "Print text to the screen. Variables are expanded automatically.",
            "flags": [("-n", "omit the trailing newline")],
            "examples": [
                ("echo hello world",    "print 'hello world'"),
                ("echo $HOME",          "print the value of the HOME variable"),
                ("echo hey > file.txt", "write 'hey' into file.txt (redirection)"),
            ],
            "tip": "Combine with > or >> to write text into files.",
        },
        "grep": {
            "desc": "Search for lines matching a pattern inside files (or piped input).",
            "flags": [
                ("-n", "show line numbers"),
                ("-i", "case-insensitive match"),
                ("-v", "invert: show lines that do NOT match"),
                ("-r", "recursive: search all files under a directory"),
                ("-c", "count matching lines instead of printing them"),
            ],
            "examples": [
                ("grep root /etc/passwd",         "find lines containing 'root'"),
                ("grep -n error /var/log/syslog", "show line numbers for 'error'"),
                ("cat file.txt | grep foo",       "search piped input"),
            ],
            "tip": "Chain with pipes: ls | grep .txt",
        },
        "find": {
            "desc": "Search for files and directories by name or type.",
            "flags": [
                ("-name <pat>", "match filename with glob pattern (* and ?)"),
                ("-type f",     "match only regular files"),
                ("-type d",     "match only directories"),
            ],
            "examples": [
                ("find /home -name '*.txt'", "find all .txt files under /home"),
                ("find . -type d",           "find all directories below current dir"),
            ],
            "tip": "Combine -name and -type for precise searches.",
        },
        "ping": {
            "desc": "Check if a remote host is reachable and measure latency.",
            "flags": [("-c N", "send only N packets (default 4)")],
            "examples": [
                ("ping 192.168.0.1",       "ping the gateway"),
                ("ping -c 2 192.168.0.10", "send only 2 packets"),
            ],
            "tip": "High rtt values mean a slow or congested link.",
        },
        "scan": {
            "desc": "Scan the virtual network and list all discovered hosts and open ports.",
            "flags": [],
            "examples": [
                ("scan",             "scan entire 192.168.0.0/24 network"),
                ("scan 192.168.0.1", "scan only hosts starting with that prefix"),
            ],
            "tip": "Note which ports are open – they tell you what services are running.",
        },
        "connect": {
            "desc": "Connect to a network host via simulated SSH.",
            "flags": [],
            "examples": [
                ("connect 192.168.0.1",  "connect to the gateway (no password)"),
                ("connect 192.168.0.25", "connect to db-server (needs password)"),
            ],
            "tip": "Scan first to find hosts, then try to connect. Some require passwords!",
        },
        "nano": {
            "desc": "Open the interactive text editor.",
            "flags": [],
            "examples": [
                ("nano file.txt",        "open or create file.txt for editing"),
                ("nano scripts/scan.sh", "edit a script"),
            ],
            "tip": (
                "Controls inside nano:\n"
                "  Arrow keys   – move cursor\n"
                "  Ctrl+S       – save\n"
                "  Ctrl+Q / Ctrl+X – quit\n"
                "  Ctrl+K       – cut current line\n"
                "  Ctrl+U       – paste cut line\n"
                "  Ctrl+G       – show help inside nano"
            ),
        },
        "run": {
            "desc": "Execute a shell script file. The file must have execute permission.",
            "flags": [],
            "examples": [
                ("run myscript.sh",         "run a script in the current directory"),
                ("run script.sh arg1 arg2", "pass arguments accessible as $1 $2"),
            ],
            "tip": "Don't forget: chmod +x script.sh before running it!",
        },
        "chmod": {
            "desc": "Change file permissions (who can read/write/execute a file).",
            "flags": [],
            "examples": [
                ("chmod +x script.sh",  "make script.sh executable"),
                ("chmod 755 script.sh", "rwx for owner, rx for group+others"),
                ("chmod 644 file.txt",  "rw for owner, r for group+others"),
            ],
            "tip": "Scripts must have +x before you can run them with 'run'.",
        },
        "export": {
            "desc": "Set or display environment variables available to all commands.",
            "flags": [],
            "examples": [
                ("export",                    "list all current environment variables"),
                ("export TARGET=192.168.0.25","set TARGET variable"),
            ],
            "tip": "Variables set with 'export' persist for the whole session.",
        },
        "history": {
            "desc": "Show a numbered list of previously entered commands.",
            "flags": [],
            "examples": [
                ("history",    "show all history"),
                ("history 10", "show last 10 commands"),
            ],
            "tip": "Press the UP arrow key to navigate through history interactively.",
        },
        "alias": {
            "desc": "Create a shortcut name for a longer command.",
            "flags": [],
            "examples": [
                ("alias",            "list all currently defined aliases"),
                ("alias ll='ls -la'","create alias ll for ls -la"),
            ],
            "tip": "Aliases only last for this session.",
        },
        "source": {
            "desc": "Run a script file in the current shell. Variables set inside the script remain available.",
            "flags": [],
            "examples": [("source setup.sh", "run setup.sh and keep its variables")],
            "tip": "Unlike 'run', source shares the current shell's variables with the script.",
        },
        "curl": {
            "desc": "Transfer data from a URL (like a web browser in the terminal).",
            "flags": [
                ("-s",        "silent: suppress progress output"),
                ("-o <file>", "save response to a file instead of printing it"),
            ],
            "examples": [
                ("curl http://192.168.0.10",              "fetch the web server homepage"),
                ("curl -o page.html http://192.168.0.10", "save page to file"),
            ],
            "tip": "curl is great for exploring web services and APIs from the terminal.",
        },
        "ps": {
            "desc": "Show a list of running processes.",
            "flags": [("-aux", "show all processes from all users")],
            "examples": [("ps", "show processes"), ("ps -aux", "show all processes")],
            "tip": "Note the PID column – you need the PID to kill a process.",
        },
        "kill": {
            "desc": "Terminate a running process by its PID.",
            "flags": [("-9", "SIGKILL – force kill, cannot be caught by the process")],
            "examples": [
                ("kill 1001",    "send SIGTERM to process 1001"),
                ("kill -9 1001", "force kill process 1001"),
            ],
            "tip": "Use ps first to find the PID of the process you want to stop.",
        },
        "diff": {
            "desc": "Compare two files line by line and show the differences.",
            "flags": [],
            "examples": [("diff file1.txt file2.txt", "show differences between two files")],
            "tip": "Lines starting with < are from file1, > are from file2.",
        },
        "man": {
            "desc": "Display the manual page for a command.",
            "flags": [],
            "examples": [("man ls", "manual for ls"), ("man grep", "manual for grep")],
            "tip": "You can also use 'help <command>' for a shorter quick reference.",
        },
    }

    def help(self, args: list = None) -> None:
        if args:
            cmd_name = args[0]
            if cmd_name in self.HELP_DETAIL:
                detail = self.HELP_DETAIL[cmd_name]
                usage  = self.commands[cmd_name].usage if cmd_name in self.commands else cmd_name
                print(f"\n  ╔══ {cmd_name} ══")
                print(f"  ║  {detail['desc']}")
                print(f"  ║")
                print(f"  ║  USAGE:  {usage}")
                if detail["flags"]:
                    print(f"  ║\n  ║  FLAGS:")
                    for flag, fdesc in detail["flags"]:
                        print(f"  ║    {flag:<16}  {fdesc}")
                if detail["examples"]:
                    print(f"  ║\n  ║  EXAMPLES:")
                    for ex_cmd, ex_desc in detail["examples"]:
                        print(f"  ║    $ {ex_cmd}")
                        print(f"  ║      → {ex_desc}")
                if detail.get("tip"):
                    lines = detail["tip"].splitlines()
                    print(f"  ║")
                    for i, ln in enumerate(lines):
                        print(f"  ║  {'TIP: ' if i == 0 else '      '}{ln}")
                print(f"  ╚{'═' * 50}\n")
            elif cmd_name in self.commands:
                cmd = self.commands[cmd_name]
                print(f"\n  {cmd.usage}\n  {cmd.description}\n")
            else:
                print(f"  No help available for '{cmd_name}'")
        else:
            print("\n  Cyber Shell Lab — Command Reference")
            print("  " + "─" * 50)
            print("  Tip: type  help <command>  for detailed help with examples\n")
            groups = {
                "File System":  ["ls", "cd", "pwd", "cat", "nano", "mkdir", "touch", "rm", "cp", "mv",
                                  "grep", "find", "head", "tail", "wc", "sort", "uniq", "cut", "diff",
                                  "chmod", "chown", "stat", "du", "df", "file"],
                "Text & Shell": ["echo", "printf", "export", "unset", "read", "alias", "type",
                                  "which", "whoami", "id", "hostname", "uname", "uptime", "date",
                                  "history", "sleep", "true", "false", "test", "env", "printenv", "xargs"],
                "Process":      ["ps", "kill", "jobs"],
                "Network":      ["ping", "scan", "connect", "ifconfig", "ip", "netstat",
                                  "curl", "wget", "traceroute", "nslookup"],
                "Scripting":    ["run", "source", "help", "man", "clear", "exit"],
            }
            for group, names in groups.items():
                print(f"  {group}:")
                for n in names:
                    if n in self.commands:
                        cmd    = self.commands[n]
                        marker = "✦" if n in self.HELP_DETAIL else " "
                        print(f"    {marker} {cmd.usage:<38} {cmd.description}")
                print()
            print("  ✦ = detailed help available  (try: help grep)")

    def man_cmd(self, args: list) -> None:
        if not args:
            print("What manual page do you want?"); return
        cmd_name = args[0]
        if cmd_name not in self.commands:
            print(f"No manual entry for {cmd_name}")
            self.env.last_exit_code = 1
            return
        cmd = self.commands[cmd_name]
        print(f"\nNAME\n       {cmd_name} — {cmd.description}")
        print(f"\nSYNOPSIS\n       {cmd.usage}")
        if cmd_name in self.HELP_DETAIL:
            d = self.HELP_DETAIL[cmd_name]
            print(f"\nDESCRIPTION\n       {d['desc']}")
            if d["flags"]:
                print("\nOPTIONS")
                for flag, fdesc in d["flags"]:
                    print(f"       {flag:<16}  {fdesc}")
            if d["examples"]:
                print("\nEXAMPLES")
                for ex_cmd, ex_desc in d["examples"]:
                    print(f"       $ {ex_cmd}\n         {ex_desc}")
            if d.get("tip"):
                print("\nNOTES")
                for ln in d["tip"].splitlines():
                    print(f"       {ln}")
        else:
            print(f"\nDESCRIPTION\n       {cmd.description}.")
        print()


# ===========================================================================
# MAIN – entry point (also used by cli.py)
# ===========================================================================

def main() -> None:
    """Build the virtual environment and run the interactive REPL.

    Input backend:
    1. readline (if available) – arrow-key history + tab-completion.
    2. plain input()           – universal fallback.

    Ctrl+C at prompt: clear line (like real bash), don't exit.
    Ctrl+D: exit.
    """
    env       = VirtualEnvironment()
    shell     = Shell(env)
    completer = ShellCompleter(shell, env)

    print("╔══════════════════════════════════════════════════╗")
    print("║         Cyber Shell Lab  –  Virtual Terminal     ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"   Logged in as  {env.user}@{env.hostname:<20} ")
    print("║  Type  help   to see available commands          ║")
    print("║  Arrow ↑/↓  history  |  Tab  autocomplete        ║")
    print("╚══════════════════════════════════════════════════╝\n")

    if _RL_AVAILABLE:
        _readline.set_completer(completer.readline_match)
        doc = getattr(_readline, "__doc__", "") or ""
        if "libedit" in doc:
            _readline.parse_and_bind("bind ^I rl_complete")
        else:
            _readline.parse_and_bind("tab: complete")
        _readline.set_completer_delims(" \t\n;|&")

    while True:
        try:
            path       = shell.get_path(env.cwd)
            prompt_str = f"{env.user}@{env.hostname}:{path}$ "
            line       = input(prompt_str)
        except EOFError:
            print("\nlogout")
            break
        except KeyboardInterrupt:
            print()
            env.last_exit_code = 130
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


if __name__ == "__main__":
    main()