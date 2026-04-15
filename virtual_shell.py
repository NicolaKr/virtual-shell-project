import shlex
import time
import re
from dataclasses import dataclass, field
from typing import Callable, Optional


# =========================================================
# FILE SYSTEM NODE
# =========================================================
class Node:
    def __init__(self, name, parent=None, is_dir=True, content=None, permissions=None, owner="student"):
        self.name = name
        self.parent = parent
        self.is_dir = is_dir
        self.content = content or ""
        self.owner = owner
        self.permissions = permissions or ("rwxr-xr-x" if is_dir else "rw-r--r--")

        self.children = {}

    @property
    def size(self):
        if self.is_dir:
            return 4096
        return len(self.content.encode())

    def permission_bits(self):
        """Return integer permission bits from rwx string."""
        p = self.permissions
        result = 0
        mapping = {"r": 4, "w": 2, "x": 1}
        for i, ch in enumerate(p):
            if ch != "-":
                result |= mapping[ch] << (6 - (i // 3) * 3)
        return result


# =========================================================
# VIRTUAL ENVIRONMENT
# =========================================================
class VirtualEnvironment:
    def __init__(self):
        self.root = Node("/", permissions="rwxr-xr-x")
        self.cwd = self.root
        self.vars = {}
        self.user = "student"
        self.hostname = "cyber-lab"

        # File system
        home = Node("home", self.root, permissions="rwxr-xr-x")
        etc  = Node("etc",  self.root, permissions="rwxr-xr-x")
        bin_ = Node("bin",  self.root, permissions="rwxr-xr-x")
        var  = Node("var",  self.root, permissions="rwxr-xr-x")

        self.root.children = {
            "home": home, "etc": etc, "bin": bin_, "var": var
        }

        home.children["student.txt"] = Node(
            "student.txt", home, False, "welcome to the cyber lab\ngood luck on your mission"
        )
        home.children["notes.txt"] = Node(
            "notes.txt", home, False, "hint: scan the network\ntarget range: 192.168.0.0/24"
        )
        home.children["readme.md"] = Node(
            "readme.md", home, False,
            "# Cyber Lab\n\nObjective: find the flag hidden on the network.\n\n## Steps\n1. Scan the network\n2. Connect to open hosts\n3. Capture the flag"
        )

        etc.children["hosts"] = Node(
            "hosts", etc, False, "127.0.0.1 localhost\n::1       localhost"
        )
        etc.children["passwd"] = Node(
            "passwd", etc, False, "root:x:0:0:root:/root:/bin/bash\nstudent:x:1000:1000::/home/student:/bin/bash",
            permissions="rw-r--r--"
        )

        # Network (CTF world)
        self.network = {
            "192.168.0.1":  {"name": "router",     "ports": [22, 80]},
            "192.168.0.10": {"name": "web-server",  "ports": [80, 443]},
            "192.168.0.25": {
                "name": "db-server",
                "ports": [3306],
                "flag": "FLAG{database_breach_9a3f}"
            },
        }


# =========================================================
# COMMAND DESCRIPTOR
# =========================================================
@dataclass
class Command:
    name:        str
    usage:       str
    description: str
    fn:          Callable


# =========================================================
# SHELL ENGINE
# =========================================================
class Shell:
    def __init__(self, env: VirtualEnvironment):
        self.env = env
        self._history: list[str] = []

        self.commands: dict[str, Command] = {}
        for cmd in [
            # filesystem
            Command("ls",      "ls [-la] [path]",      "list directory contents",       self.ls),
            Command("cd",      "cd <path>",             "change directory",              self.cd),
            Command("pwd",     "pwd",                   "print working directory",       self.pwd),
            Command("cat",     "cat <file>",            "print file contents",           self.cat),
            Command("nano",    "nano <file>",           "edit a file interactively",     self.nano),
            Command("mkdir",   "mkdir <dir>",           "create a directory",            self.mkdir),
            Command("touch",   "touch <file>",          "create an empty file",          self.touch),
            Command("rm",      "rm [-r] <path>",        "remove file or directory",      self.rm),
            Command("cp",      "cp <src> <dst>",        "copy a file",                   self.cp),
            Command("mv",      "mv <src> <dst>",        "move or rename a file",         self.mv),
            Command("grep",    "grep [-n] <pat> <file>","search pattern in file",        self.grep),
            Command("echo",    "echo <text>",           "print text",                    self.echo),
            Command("export",  "export [KEY=val]",      "set or list env variables",     self.export),
            Command("chmod",   "chmod <mode> <file>",   "change file permissions",       self.chmod),
            Command("head",    "head [-n N] <file>",    "print first N lines",           self.head),
            Command("tail",    "tail [-n N] <file>",    "print last N lines",            self.tail),
            Command("wc",      "wc [-lwc] <file>",      "word/line/char count",          self.wc),
            Command("which",   "which <cmd>",           "locate a command",              self.which),
            Command("whoami",  "whoami",                "print current user",            self.whoami),
            Command("hostname","hostname",              "print hostname",                self.hostname_cmd),
            Command("history", "history",               "show command history",          self.history_cmd),
            Command("read",    "read <var>",            "read input into variable",      self.read),
            # network
            Command("ping",    "ping <ip>",             "check if host is alive",        self.ping),
            Command("scan",    "scan [prefix]",         "scan the network",              self.scan),
            Command("connect", "connect <ip>",          "connect to a host",             self.connect),
            # scripting
            Command("run",     "run <file.sh>",         "execute a shell script",        self.run_script),
            # meta
            Command("help",    "help [command]",        "show this help",                self.help),
            Command("clear",   "clear",                 "clear screen",                  self.clear),
        ]:
            self.commands[cmd.name] = cmd

    # =====================================================
    # MAIN DISPATCH
    # =====================================================
    def run(self, line: str, _capture=False) -> Optional[str]:
        """
        Execute one line. If _capture=True, return stdout as a string
        instead of printing it (used for pipe implementation).
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return

        # record history (skip duplicates of last entry)
        if not self._history or self._history[-1] != line:
            self._history.append(line)

        # ---- operator splitting: handle &&  ||  |  ----------------------
        # We handle a single level of chaining; nested ops not supported.

        # pipe  a | b  (only two-command pipes)
        if "|" in line and "||" not in line:
            left, right = line.split("|", 1)
            output = self._run_single(left.strip(), capture=True)
            self._run_piped(right.strip(), output or "")
            return

        # logical AND
        if "&&" in line:
            parts = line.split("&&")
            for p in parts:
                result = self.run(p.strip())
                # if a command "fails" we'd need return codes; skip for now
            return

        # logical OR
        if "||" in line:
            parts = line.split("||", 1)
            self.run(parts[0].strip())
            # real shells only run right side on failure; simplified: always run left
            return

        self._run_single(line, capture=_capture)

    def _run_single(self, line: str, capture: bool = False) -> Optional[str]:
        """Run a single command with no operators."""
        line = line.strip()
        if not line or line.startswith("#"):
            return

        # variable assignment  e.g.  TARGET=192.168.0.25
        if (
            "=" in line
            and not line.startswith("export")
            and not line.startswith("scan")
            and not line.startswith("echo")
        ):
            key, _, value = line.partition("=")
            if " " not in key.strip():
                self.env.vars[key.strip()] = self._expand_vars(value.strip())
                return

        line = self._expand_vars(line)

        if line.startswith("./"):
            return self._dispatch("run", [line[2:]], capture)

        try:
            parts = shlex.split(line)
        except Exception:
            self._print("parse error", capture)
            return

        cmd, args = parts[0], parts[1:]

        if cmd in self.commands:
            if capture:
                import io, sys
                buf = io.StringIO()
                old = sys.stdout
                sys.stdout = buf
                try:
                    self.commands[cmd].fn(args)
                finally:
                    sys.stdout = old
                return buf.getvalue()
            else:
                self.commands[cmd].fn(args)
        else:
            print(f"bash: command not found: {cmd}")

    def _dispatch(self, cmd, args, capture):
        if capture:
            import io, sys
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                self.commands[cmd].fn(args)
            finally:
                sys.stdout = old
            return buf.getvalue()
        else:
            self.commands[cmd].fn(args)

    def _run_piped(self, right_cmd: str, stdin_text: str):
        """Run right side of a pipe, injecting stdin_text."""
        right_cmd = self._expand_vars(right_cmd.strip())
        try:
            parts = shlex.split(right_cmd)
        except Exception:
            print("parse error")
            return
        cmd, args = parts[0], parts[1:]

        # Commands that can meaningfully receive piped input
        if cmd == "grep":
            if not args:
                print("grep: missing pattern")
                return
            pattern = args[0]
            for ln in stdin_text.splitlines():
                if pattern in ln:
                    print(ln)
        elif cmd == "wc":
            self._wc_text(stdin_text, args)
        elif cmd == "head":
            n = self._flag_n(args, 10)
            lines = stdin_text.splitlines()
            print("\n".join(lines[:n]))
        elif cmd == "tail":
            n = self._flag_n(args, 10)
            lines = stdin_text.splitlines()
            print("\n".join(lines[-n:]))
        elif cmd == "cat":
            print(stdin_text, end="")
        elif cmd in self.commands:
            self.commands[cmd].fn(args)
        else:
            print(f"bash: command not found: {cmd}")

    def _expand_vars(self, text: str) -> str:
        for k, v in self.env.vars.items():
            text = re.sub(rf"\${k}\b", v, text)
        return text

    def _print(self, msg, capture=False):
        print(msg)

    # =====================================================
    # PATH HELPERS
    # =====================================================
    def resolve_path(self, path: str) -> Node:
        if not path or path == ".":
            return self.env.cwd
        if path in ("~", f"/home/{self.env.user}"):
            return self.env.root.children.get("home", self.env.root)

        node = self.env.root if path.startswith("/") else self.env.cwd
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
        parts = []
        cur = node
        while cur.parent is not None:
            parts.append(cur.name)
            cur = cur.parent
        return "/" + "/".join(reversed(parts)) if parts else "/"

    def _resolve_dest(self, dest_str, src_name):
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

    # =====================================================
    # FILESYSTEM COMMANDS
    # =====================================================
    def ls(self, args):
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        long    = any("l" in f for f in flags)
        # -a flag would show hidden files; skipping dot-files for brevity

        try:
            node = self.resolve_path(targets[0]) if targets else self.env.cwd
        except FileNotFoundError as e:
            print(e); return

        if not node.is_dir:
            if long:
                self._ls_long_line(node)
            else:
                print(node.name)
            return

        entries = sorted(node.children.values(), key=lambda n: n.name)
        if not entries:
            print("(empty)"); return

        if long:
            total_blocks = sum(max(1, n.size // 512) for n in entries)
            print(f"total {total_blocks}")
            for n in entries:
                self._ls_long_line(n)
        else:
            # colorize dirs (simulate) by adding / suffix
            names = [n.name + ("/" if n.is_dir else "") for n in entries]
            print("  ".join(names))

    def _ls_long_line(self, node: Node):
        kind    = "d" if node.is_dir else "-"
        perms   = kind + node.permissions
        nlinks  = len(node.children) + 2 if node.is_dir else 1
        owner   = node.owner
        size    = node.size
        # fake mtime
        mtime   = "Apr 10 12:34"
        print(f"{perms}  {nlinks:2}  {owner:<8} {owner:<8} {size:6}  {mtime}  {node.name}")

    def cd(self, args):
        if not args:
            # cd with no args goes home
            home = self.env.root.children.get("home")
            if home:
                self.env.cwd = home
            return
        try:
            node = self.resolve_path(args[0])
        except FileNotFoundError as e:
            print(e); return
        if not node.is_dir:
            print(f"cd: not a directory: {args[0]}"); return
        self.env.cwd = node

    def pwd(self, args):
        print(self.get_path(self.env.cwd))

    def cat(self, args):
        if not args:
            print("usage: cat <file>"); return
        for path in args:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError as e:
                print(e); continue
            if node.is_dir:
                print(f"cat: {path}: is a directory")
            else:
                print(node.content, end="" if node.content.endswith("\n") else "\n")

    def mkdir(self, args):
        if not args:
            print("usage: mkdir <dir>"); return
        for path in args:
            try:
                parent = self.env.cwd
                name   = path
                if "/" in path:
                    head, name = path.rsplit("/", 1)
                    parent = self.resolve_path(head)
                if name in parent.children:
                    print(f"mkdir: cannot create directory '{path}': file exists"); continue
                new_node = Node(name, parent, is_dir=True, owner=self.env.user)
                new_node.children = {}
                parent.children[name] = new_node
            except FileNotFoundError as e:
                print(e)

    def touch(self, args):
        if not args:
            print("usage: touch <file>"); return
        for path in args:
            try:
                parent = self.env.cwd
                name   = path
                if "/" in path:
                    head, name = path.rsplit("/", 1)
                    parent = self.resolve_path(head)
                if name not in parent.children:
                    parent.children[name] = Node(name, parent, is_dir=False, content="", owner=self.env.user)
            except FileNotFoundError as e:
                print(e)

    def rm(self, args):
        if not args:
            print("usage: rm [-r] <path>"); return
        flags   = {a for a in args if a.startswith("-")}
        targets = [a for a in args if not a.startswith("-")]
        recursive = "-r" in flags or "-rf" in flags or "-fr" in flags

        for path in targets:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError as e:
                print(e); continue
            if node.is_dir and not recursive:
                print(f"rm: cannot remove '{path}': is a directory"); continue
            if node.parent is None:
                print("rm: cannot remove root"); continue
            node.parent.children.pop(node.name)

    def cp(self, args):
        if len(args) < 2:
            print("usage: cp <src> <dst>"); return
        try:
            src = self.resolve_path(args[0])
        except FileNotFoundError as e:
            print(e); return
        if src.is_dir:
            print("cp: omitting directory (use cp -r)"); return
        try:
            dest_parent, dest_name = self._resolve_dest(args[1], src.name)
        except FileNotFoundError as e:
            print(e); return
        dest_parent.children[dest_name] = Node(
            dest_name, dest_parent, is_dir=False,
            content=src.content, permissions=src.permissions, owner=self.env.user
        )

    def mv(self, args):
        if len(args) < 2:
            print("usage: mv <src> <dst>"); return
        try:
            src = self.resolve_path(args[0])
        except FileNotFoundError as e:
            print(e); return
        try:
            dest_parent, dest_name = self._resolve_dest(args[1], src.name)
        except FileNotFoundError as e:
            print(e); return
        if src.parent:
            src.parent.children.pop(src.name)
        src.name   = dest_name
        src.parent = dest_parent
        dest_parent.children[dest_name] = src

    def grep(self, args):
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        show_num = "-n" in flags

        if len(targets) < 2:
            print("usage: grep [-n] <pattern> <file>"); return
        pattern, file_path = targets[0], targets[1]
        try:
            node = self.resolve_path(file_path)
        except FileNotFoundError as e:
            print(e); return
        if node.is_dir:
            print("grep: is a directory"); return
        for i, ln in enumerate(node.content.splitlines(), 1):
            if pattern in ln:
                print(f"{i}:{ln}" if show_num else ln)

    def echo(self, args):
        # handle -n flag (no trailing newline)
        if args and args[0] == "-n":
            print(" ".join(args[1:]), end="")
        else:
            print(" ".join(args))

    def export(self, args):
        if not args:
            for k, v in self.env.vars.items():
                print(f"declare -x {k}=\"{v}\"")
            return
        for arg in args:
            if "=" in arg:
                k, _, v = arg.partition("=")
                self.env.vars[k.strip()] = v.strip()

    def read(self, args):
        if not args:
            print("usage: read <var>"); return
        var = args[0]
        try:
            value = input()
        except EOFError:
            value = ""
        self.env.vars[var] = value

    # =====================================================
    # CHMOD
    # =====================================================
    def chmod(self, args):
        if len(args) < 2:
            print("usage: chmod <mode> <file>"); return
        mode_str, path = args[0], args[1]
        try:
            node = self.resolve_path(path)
        except FileNotFoundError as e:
            print(e); return

        # Octal mode e.g. 755 or 644
        if re.fullmatch(r"[0-7]{3}", mode_str):
            p = ""
            for digit in mode_str:
                d = int(digit)
                p += ("r" if d & 4 else "-")
                p += ("w" if d & 2 else "-")
                p += ("x" if d & 1 else "-")
            node.permissions = p
            return

        # Symbolic mode e.g. +x  u+x  go-w  a=r  ugo+rx
        m = re.fullmatch(r"([ugoa]*)([+\-=])([rwx]+)", mode_str)
        if not m:
            print(f"chmod: invalid mode: {mode_str}"); return

        who, op, perms = m.group(1), m.group(2), m.group(3)
        if not who or who == "a":
            who = "ugo"

        p = list(node.permissions)  # 9 chars: user(0-2) group(3-5) other(6-8)
        who_map = {"u": (0, 1, 2), "g": (3, 4, 5), "o": (6, 7, 8)}
        perm_map = {"r": 0, "w": 1, "x": 2}  # offset within each triplet

        for w in who:
            offsets = who_map.get(w, ())
            for ch in perms:
                idx = offsets[perm_map[ch]]
                if op == "+":
                    p[idx] = ch
                elif op == "-":
                    p[idx] = "-"
                elif op == "=":
                    # reset all three for this who, then set
                    for i in offsets:
                        p[i] = "-"
                    p[idx] = ch

        node.permissions = "".join(p)

    # =====================================================
    # HEAD / TAIL / WC / WHICH
    # =====================================================
    def _flag_n(self, args, default=10):
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args):
                try:
                    return int(args[i + 1])
                except ValueError:
                    pass
            if re.match(r"^-\d+$", a):
                return int(a[1:])
        return default

    def _get_file_args(self, args):
        """Strip flags and return non-flag args."""
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

    def head(self, args):
        n       = self._flag_n(args)
        targets = self._get_file_args(args)
        if not targets:
            print("usage: head [-n N] <file>"); return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError as e:
            print(e); return
        if node.is_dir:
            print("head: is a directory"); return
        print("\n".join(node.content.splitlines()[:n]))

    def tail(self, args):
        n       = self._flag_n(args)
        targets = self._get_file_args(args)
        if not targets:
            print("usage: tail [-n N] <file>"); return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError as e:
            print(e); return
        if node.is_dir:
            print("tail: is a directory"); return
        print("\n".join(node.content.splitlines()[-n:]))

    def wc(self, args):
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: wc [-lwc] <file>"); return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError as e:
            print(e); return
        if node.is_dir:
            print("wc: is a directory"); return
        self._wc_text(node.content, args, targets[0])

    def _wc_text(self, text, flags_args, label=""):
        lines = text.splitlines()
        words = text.split()
        chars = len(text)
        flags = [a for a in flags_args if a.startswith("-")]
        if not flags or (set("".join(flags)) & {"l", "w", "c"} == set()):
            print(f"  {len(lines):4}  {len(words):4}  {chars:4}  {label}")
        else:
            parts = []
            joined = "".join(flags)
            if "l" in joined: parts.append(f"{len(lines):4}")
            if "w" in joined: parts.append(f"{len(words):4}")
            if "c" in joined: parts.append(f"{chars:4}")
            print("  ".join(parts) + (f"  {label}" if label else ""))

    def which(self, args):
        if not args:
            print("usage: which <command>"); return
        for cmd in args:
            if cmd in self.commands:
                print(f"/usr/bin/{cmd}")
            else:
                print(f"which: no {cmd} in PATH")

    def whoami(self, args):
        print(self.env.user)

    def hostname_cmd(self, args):
        print(self.env.hostname)

    def history_cmd(self, args):
        for i, entry in enumerate(self._history, 1):
            print(f"  {i:3}  {entry}")

    def clear(self, args):
        print("\033[2J\033[H", end="")

    # =====================================================
    # NANO EDITOR  (improved)
    # =====================================================
    def nano(self, args):
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

        # Load existing content
        if name in parent.children and not parent.children[name].is_dir:
            existing = parent.children[name].content
        else:
            existing = ""

        ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
        hints = {
            "py": "Python", "sh": "Shell script", "txt": "Text",
            "md": "Markdown", "json": "JSON", "js": "JavaScript",
            "html": "HTML", "css": "CSS", "c": "C", "cpp": "C++",
            "rs": "Rust", "go": "Go", "yaml": "YAML", "rb": "Ruby",
        }
        hint = hints.get(ext, "File")
        lines = existing.splitlines()

        print(f"\n  nano — {hint}: {filename}")
        print("  ─────────────────────────────────────────────────────")
        print("  Commands:  :wq save & quit  |  :q! cancel  |  :a append mode")
        print("             N: <text>  edit line N  |  :d N  delete line N")
        print("             :i N <text>  insert before line N")
        print("  ─────────────────────────────────────────────────────\n")

        def show_buffer():
            if not lines:
                print("  (empty file)")
            else:
                for i, ln in enumerate(lines, 1):
                    print(f"  {i:3} | {ln}")
            print()

        show_buffer()

        while True:
            try:
                raw = input("  nano> ").rstrip("\n")
            except EOFError:
                break

            # ---- quit commands ----
            if raw.strip() == ":wq":
                break
            if raw.strip() == ":q!":
                print("  cancelled — no changes saved")
                return

            # ---- show current state ----
            if raw.strip() in (":s", ":show", ":l", ":list"):
                show_buffer()
                continue

            # ---- delete line  :d N ----
            m = re.fullmatch(r":d\s+(\d+)", raw.strip())
            if m:
                idx = int(m.group(1)) - 1
                if 0 <= idx < len(lines):
                    removed = lines.pop(idx)
                    print(f"  deleted line {idx+1}: {removed}")
                else:
                    print(f"  error: line {idx+1} does not exist")
                show_buffer()
                continue

            # ---- insert before line  :i N <text> ----
            m = re.fullmatch(r":i\s+(\d+)\s+(.*)", raw.strip(), re.DOTALL)
            if m:
                idx  = int(m.group(1)) - 1
                text = m.group(2)
                lines.insert(max(0, idx), text)
                print(f"  inserted before line {idx+1}")
                show_buffer()
                continue

            # ---- append mode  :a ----
            if raw.strip() == ":a":
                print("  append mode — type lines, enter ':done' to finish\n")
                while True:
                    try:
                        ln = input("  + ")
                    except EOFError:
                        break
                    if ln.strip() == ":done":
                        break
                    lines.append(ln)
                show_buffer()
                continue

            # ---- edit line  N: <new text> ----
            m = re.fullmatch(r"(\d+):\s*(.*)", raw.strip(), re.DOTALL)
            if m:
                idx  = int(m.group(1)) - 1
                text = m.group(2)
                if 0 <= idx < len(lines):
                    lines[idx] = text
                    print(f"  updated line {idx+1}")
                elif idx == len(lines):
                    lines.append(text)
                    print(f"  appended as line {idx+1}")
                else:
                    print(f"  error: line {idx+1} out of range (file has {len(lines)} lines)")
                show_buffer()
                continue

            # ---- plain text → append ----
            if raw:
                lines.append(raw)
                print(f"  appended line {len(lines)}")
                continue

        content = "\n".join(lines)
        if name in parent.children:
            parent.children[name].content = content
        else:
            parent.children[name] = Node(
                name, parent, is_dir=False, content=content,
                owner=self.env.user
            )
        print(f'\n  saved "{filename}" ({len(lines)} lines)\n')

    # =====================================================
    # NETWORK COMMANDS
    # =====================================================
    def ping(self, args):
        if not args:
            print("usage: ping <ip>"); return
        ip = args[0]
        if ip in self.env.network:
            host = self.env.network[ip]
            print(f"PING {ip} ({host['name']}): 56 data bytes")
            for i in range(3):
                ms = round(0.4 + i * 0.1, 1)
                print(f"64 bytes from {ip}: icmp_seq={i} ttl=64 time={ms} ms")
        else:
            print(f"ping: cannot reach {ip}: No route to host")

    def scan(self, args):
        print("[*] scanning network...\n")
        time.sleep(0.2)
        prefix = args[0] if args else ""
        found  = False
        for ip, info in self.env.network.items():
            if not prefix or ip.startswith(prefix):
                ports = ", ".join(str(p) for p in info["ports"])
                print(f"  {ip:<18}  {info['name']:<14}  ports: {ports}")
                found = True
        if not found:
            print("  no hosts found")
        print()

    def connect(self, args):
        if not args:
            print("usage: connect <ip>"); return
        ip = args[0]
        if ip not in self.env.network:
            print(f"connect: {ip}: Connection refused"); return
        host = self.env.network[ip]
        print(f"Connecting to {ip} ({host['name']})...")
        time.sleep(0.1)
        print(f"Connected.")
        print(f"Open ports: {host['ports']}")
        if "flag" in host:
            print(f"\n  *** FLAG CAPTURED ***")
            print(f"  {host['flag']}")
            print()

    # =====================================================
    # SCRIPT ENGINE
    # =====================================================
    def run_script(self, args):
        if not args:
            print("usage: run <file.sh>"); return
        try:
            node = self.resolve_path(args[0])
        except FileNotFoundError as e:
            print(f"run: {e}"); return
        if node.is_dir:
            print("run: is a directory"); return

        # check execute permission
        if "x" not in node.permissions[:3]:
            print(f"run: permission denied: {args[0]} (hint: chmod +x {args[0]})"); return

        for raw in node.content.splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            self.run(stripped)

    # =====================================================
    # HELP
    # =====================================================
    def help(self, args=None):
        if args and args[0] in self.commands:
            cmd = self.commands[args[0]]
            print(f"\n  {cmd.usage}")
            print(f"  {cmd.description}\n")
        else:
            print("\nAvailable commands:\n")
            groups = {
                "File system": ["ls","cd","pwd","cat","nano","mkdir","touch","rm","cp","mv","grep","head","tail","wc","chmod"],
                "Text":        ["echo","export","read"],
                "Network":     ["ping","scan","connect"],
                "Shell":       ["run","history","which","whoami","hostname","clear","help"],
            }
            for group, names in groups.items():
                print(f"  {group}:")
                for n in names:
                    if n in self.commands:
                        cmd = self.commands[n]
                        print(f"    {cmd.usage:<32} {cmd.description}")
                print()


# =========================================================
# MAIN LOOP
# =========================================================
def main():
    from virtual_shell import VirtualEnvironment, Shell

    env   = VirtualEnvironment()
    shell = Shell(env)

    print(f"Cyber Shell Lab  |  type 'help' for commands")
    print(f"Logged in as {env.user}@{env.hostname}\n")

    while True:
        try:
            path = shell.get_path(env.cwd)
            line = input(f"{env.user}@{env.hostname}:{path}$ ")
        except (EOFError, KeyboardInterrupt):
            print("\nlogout")
            break

        if line.strip() == "exit":
            print("logout")
            break

        shell.run(line)


if __name__ == "__main__":
    main()