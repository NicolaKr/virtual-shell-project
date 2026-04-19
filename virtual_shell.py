import shlex
import time
import re
import random
import datetime
from dataclasses import dataclass, field
from typing import Callable, Optional
import io
import sys

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
        self.mtime = "Apr 10 12:34"

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
        self.vars = {
            "HOME": "/home/student",
            "USER": "student",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
        }
        self.user = "student"
        self.hostname = "cyber-lab"
        self.last_exit_code = 0  # $? support

        # File system
        home    = Node("home", self.root, permissions="rwxr-xr-x")
        etc     = Node("etc",  self.root, permissions="rwxr-xr-x")
        bin_    = Node("bin",  self.root, permissions="rwxr-xr-x")
        var     = Node("var",  self.root, permissions="rwxr-xr-x")
        tmp     = Node("tmp",  self.root, permissions="rwxrwxrwx")
        usr     = Node("usr",  self.root, permissions="rwxr-xr-x")

        self.root.children = {
            "home": home, "etc": etc, "bin": bin_, "var": var, "tmp": tmp, "usr": usr
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
        home.children["scripts"] = Node("scripts", home, True)
        home.children["scripts"].children = {}

        etc.children["hosts"] = Node(
            "hosts", etc, False,
            "127.0.0.1 localhost\n::1       localhost\n192.168.0.1 gateway-router\n192.168.0.10 web-server\n192.168.0.25 db-server"
        )
        etc.children["passwd"] = Node(
            "passwd", etc, False,
            "root:x:0:0:root:/root:/bin/bash\nstudent:x:1000:1000::/home/student:/bin/bash\ndbadmin:x:1001:1001::/home/dbadmin:/bin/bash",
            permissions="rw-r--r--"
        )
        etc.children["os-release"] = Node(
            "os-release", etc, False,
            'NAME="Cyber Lab Linux"\nVERSION="1.0"\nID=cyberlab\nPRETTY_NAME="Cyber Lab Linux 1.0"\nHOME_URL="https://cyberlab.example.com"'
        )

        var.children["log"] = Node("log", var, True)
        var.children["log"].children = {
            "syslog": Node("syslog", var.children["log"], False,
                           "Apr 10 09:00:01 cyber-lab kernel: Booting...\nApr 10 09:00:12 cyber-lab sshd: Server listening on 0.0.0.0 port 22.\nApr 10 09:01:45 cyber-lab cron[123]: Job started")
        }


        # =====================================================
        # network definition with auth metadata
        #
        # Each host now supports:
        #   "public"    – True = no password needed
        #   "password"  – required when public=False
        #   "auth_user" – username shown at the login prompt
        #   "banner"    – SSH/service banner printed on connect
        #   "services"  – dict of port → service name (used by scan)
        #   "os"        – OS string shown in banner
        #   "latency"   – base round-trip ms (ping realism)
        #   "flag"      – CTF flag (optional)
        #   "shell_hint"– extra line shown after successful login
        # =====================================================

        self.network = {
            "192.168.0.1": {
                "name":     "gateway-router",
                "public":   True,          # open – no password
                "services": {22: "ssh", 80: "http"},
                "os":       "RouterOS 6.49",
                "latency":  1.2,
                "banner":   (
                    "MikroTik RouterOS 6.49.6\n"
                    "Model: RB750Gr3  |  CPU: 880 MHz  |  RAM: 256 MB\n"
                    "Uptime: 47d 13h 22m"
                ),
                "shell_hint": "Try: show arp, show routes, show interfaces",
            },
            "192.168.0.10": {
                "name":     "web-server",
                "public":   True,          # open – no password
                "services": {80: "http", 443: "https", 22: "ssh"},
                "os":       "Ubuntu 22.04 LTS",
                "latency":  3.7,
                "banner":   (
                    "Ubuntu 22.04.3 LTS  (GNU/Linux 5.15.0-91-generic x86_64)\n"
                    "Apache/2.4.57 running on :80  |  nginx/1.24 on :443\n"
                    "Last login: Thu Apr 10 09:14:02 2025 from 192.168.0.5"
                ),
                "shell_hint": "Try: ls /var/www/html to browse the web root",
            },
            "192.168.0.25": {
                "name":     "db-server",
                "public":   False,                 # CHANGED: password-protected
                "password": "s3cr3tdb",            # CHANGED: correct password
                "auth_user": "dbadmin",            # CHANGED: login user shown at prompt
                "services": {3306: "mysql", 22: "ssh"},
                "os":       "Debian 11 (Bullseye)",
                "latency":  8.4,
                "banner":   (
                    "Debian GNU/Linux 11  (Linux 5.10.0-28-amd64)\n"
                    "MySQL 8.0.36 listening on 127.0.0.1:3306\n"
                    "!! Restricted system – authorised access only !!\n"
                    "Last login: Fri Apr 11 02:33:19 2025 from 192.168.0.1"
                ),
                "flag":       "FLAG{database_breach_9a3f}",
                "shell_hint": "Try: mysql -u root -p  or  cat /root/.flag",
            },
            "192.168.0.50": {
                "name":     "admin-panel",
                "public":   False,                 # CHANGED: password-protected
                "password": "admin1234",           # CHANGED: correct password
                "auth_user": "administrator",
                "services": {8080: "http-alt", 22: "ssh", 3389: "rdp"},
                "os":       "Windows Server 2019",
                "latency":  12.1,
                "banner":   (
                    "Windows Server 2019 Datacenter  Build 17763\n"
                    "Remote Desktop Services ready on :3389\n"
                    "Admin panel running on http://192.168.0.50:8080\n"
                    "WARNING: All activity on this system is monitored."
                ),
                "shell_hint": "Explore: dir C:\\Users\\Administrator\\Desktop",
            },
            "192.168.0.99": {
                "name":     "honeypot",
                "public":   False,                 # CHANGED: always rejects login
                "password": None,                  # CHANGED: None = rejects any cred
                "services": {22: "ssh", 21: "ftp", 23: "telnet"},
                "os":       "Unknown",
                "latency":  0.3,
                "banner":   "",                    # never shown – rejected before banner
                "shell_hint": "",
            },
        }

        self.authenticated = set()

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
# SCRIPT INTERPRETER  (full Bash-like scripting)
# =========================================================
class ScriptInterpreter:
    """
    Parses and executes shell scripts with:
      - Variables  ($VAR, ${VAR})
      - Arithmetic  $(( expr ))
      - Command substitution  $( cmd )
      - if / elif / else / fi
      - for VAR in LIST; do … done
      - while CONDITION; do … done
      - until CONDITION; do … done
      - break / continue
      - Output redirection  >  >>  2>  &>
      - Pipes  |
      - Functions  name() { … }
      - local VAR=val
      - return N
      - Comments  #
    """

    def __init__(self, shell: "Shell"):
        self.shell = shell
        self.env = shell.env
        self._functions: dict[str, list[str]] = {}
        self._local_vars: dict[str, str] = {}
        self._return_value: Optional[int] = None
        self._break_flag = False
        self._continue_flag = False

    def run_lines(self, lines: list[str], extra_vars: dict = None) -> int:
        """Execute a list of script lines. Returns exit code."""
        if extra_vars:
            self._local_vars.update(extra_vars)

        # first pass: collect function definitions
        lines = self._extract_functions(lines)

        idx = 0
        while idx < len(lines):
            line = lines[idx].strip()

            if not line or line.startswith("#"):
                idx += 1
                continue

            # --- if block ---
            if re.match(r"^if\s+", line) or line == "if":
                block, consumed = self._collect_block(lines, idx, "if", "fi")
                self._exec_if_block(block)
                idx += consumed
                continue

            # --- for loop ---
            if re.match(r"^for\s+", line):
                block, consumed = self._collect_loop(lines, idx)
                self._exec_for(block)
                idx += consumed
                continue

            # --- while loop ---
            if re.match(r"^while\s+", line):
                block, consumed = self._collect_loop(lines, idx)
                self._exec_while(block, invert=False)
                idx += consumed
                continue

            # --- until loop ---
            if re.match(r"^until\s+", line):
                block, consumed = self._collect_loop(lines, idx)
                self._exec_while(block, invert=True)
                idx += consumed
                continue

            # --- break / continue ---
            if line == "break":
                self._break_flag = True
                break
            if line == "continue":
                self._continue_flag = True
                break

            # --- return ---
            m = re.match(r"^return\s*(\d*)", line)
            if m:
                code = int(m.group(1)) if m.group(1) else 0
                self._return_value = code
                return code

            # --- local VAR=val ---
            m = re.match(r"^local\s+(\w+)=(.*)", line)
            if m:
                k, v = m.group(1), self._expand(m.group(2))
                self._local_vars[k] = v
                idx += 1
                continue

            self._exec_line(line)
            idx += 1

        return self.env.last_exit_code

    # ---- function collection ----

    def _extract_functions(self, lines: list[str]) -> list[str]:
        """Remove function definitions from lines and store them."""
        remaining = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = re.match(r"^(\w+)\s*\(\s*\)\s*\{?\s*$", line)

            # Single-line:  name() { body; }  or  function name() { body; }
            m_single = re.match(
                r"^(?:function\s+)?(\w+)\s*\(\s*\)\s*\{(.+)\}\s*$", line
            )
            if m_single:
                fname = m_single.group(1)
                body_text = m_single.group(2).strip()
                # split body on semicolons to get individual statements
                body_lines = [b.strip() for b in body_text.split(";") if b.strip()]
                self._functions[fname] = body_lines
                i += 1
                continue

            # Multi-line:  name() {  or  function name() {  or  name() on its own line
            m = re.match(r"^(?:function\s+)?(\w+)\s*\(\s*\)\s*\{?\s*$", line)

            if m:
                fname = m.group(1)
                body = []
                brace_open = "{" in line
                i += 1
                depth = 1 if brace_open else 0
                while i < len(lines):
                    l = lines[i].strip()
                    if not brace_open and l == "{":
                        brace_open = True
                        depth = 1
                        i += 1
                        continue
                    depth += l.count("{") - l.count("}")
                    if depth <= 0 or l == "}":
                        i += 1
                        break
                    body.append(lines[i])
                    i += 1
                self._functions[fname] = body
                continue
            remaining.append(lines[i])
            i += 1
        return remaining

    # ---- block collectors ----

    def _collect_block(self, lines, start, open_kw, close_kw):
        """Collect lines of an if/fi block."""
        block = [lines[start]]
        depth = 1
        i = start + 1
        while i < len(lines) and depth > 0:
            l = lines[i].strip()
            if re.match(rf"^{open_kw}[\s(]", l) or l == open_kw:
                depth += 1
            if l == close_kw:
                depth -= 1
                if depth == 0:
                    block.append(lines[i])
                    i += 1
                    break
            block.append(lines[i])
            i += 1
        return block, i - start

    def _collect_loop(self, lines, start):
        """Collect for/while/until … done block."""
        block = [lines[start]]
        depth = 1
        i = start + 1
        while i < len(lines) and depth > 0:
            l = lines[i].strip()
            if re.match(r"^(for|while|until)\s+", l):
                depth += 1
            if l == "done":
                depth -= 1
                if depth == 0:
                    block.append(lines[i])
                    i += 1
                    break
            block.append(lines[i])
            i += 1
        return block, i - start

    # ---- if / elif / else / fi ----

    def _exec_if_block(self, block: list[str]):
        lines = [l.strip() for l in block]
        # split into clauses: (condition_line, body_lines)
        clauses = []  # list of (cond_str | None, [body_lines])
        i = 0
        current_cond = None
        current_body = []

        while i < len(lines):
            l = lines[i]
            m_if = re.match(r"^if\s+(.*?)\s*;?\s*then\s*$", l)
            m_elif = re.match(r"^elif\s+(.*?)\s*;?\s*then\s*$", l)

            if m_if:
                current_cond = m_if.group(1)
                current_body = []
                i += 1
                # collect body until elif/else/fi
                while i < len(lines) and lines[i] not in ("else", "fi") and not re.match(r"^elif\s+", lines[i]):
                    if lines[i] != "then":
                        current_body.append(lines[i])
                    i += 1
                clauses.append((current_cond, current_body))
                continue

            if m_elif:
                current_cond = m_elif.group(1)
                current_body = []
                i += 1
                while i < len(lines) and lines[i] not in ("else", "fi") and not re.match(r"^elif\s+", lines[i]):
                    if lines[i] != "then":
                        current_body.append(lines[i])
                    i += 1
                clauses.append((current_cond, current_body))
                continue

            if l == "else":
                current_body = []
                i += 1
                while i < len(lines) and lines[i] != "fi":
                    current_body.append(lines[i])
                    i += 1
                clauses.append((None, current_body))  # None = else branch
                continue

            i += 1

        for cond, body in clauses:
            if cond is None:
                # else branch – only reached if no earlier branch matched
                self.run_lines(body)
                return
            if self._eval_condition(cond):
                self.run_lines(body)
                return # ← critical: stop after first matching branch

    # ---- condition evaluator ----

    def _eval_condition(self, cond: str) -> bool:
        cond = self._expand(cond).strip()

        # [ expr ] or [[ expr ]]
        m = re.match(r"^\[{1,2}\s*(.*?)\s*\]{1,2}$", cond)
        if m:
            return self._eval_test(m.group(1))

        # test expr
        m = re.match(r"^test\s+(.*)", cond)
        if m:
            return self._eval_test(m.group(1))

        # arithmetic (( expr ))
        m = re.match(r"^\(\(\s*(.*?)\s*\)\)$", cond)
        if m:
            try:
                return bool(eval(m.group(1), {"__builtins__": {}}))
            except Exception:
                return False

        # plain command – run and check exit code
        old_exit = self.env.last_exit_code
        self._exec_line(cond)
        result = self.env.last_exit_code == 0
        return result

    def _eval_test(self, expr: str) -> bool:
        expr = expr.strip()

        def unquote(s):
            s = s.strip()
            if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
                return s[1:-1]
            return s

        # string comparisons
        for op in ("!=", "==", "="):
            if op in expr:
                parts = expr.split(op, 1)
                if len(parts) == 2:
                    l, r = unquote(parts[0]), unquote(parts[1])
                    if op in ("==", "="):
                        return l == r
                    return l != r

        # numeric comparisons
        for op, fn in [("-eq", lambda a, b: a == b), ("-ne", lambda a, b: a != b),
                       ("-lt", lambda a, b: a < b), ("-le", lambda a, b: a <= b),
                       ("-gt", lambda a, b: a > b), ("-ge", lambda a, b: a >= b)]:
            if op in expr:
                parts = expr.split(op, 1)
                try:
                    a, b = int(unquote(parts[0])), int(unquote(parts[1]))
                    return fn(a, b)
                except ValueError:
                    return False

        # file tests
        m = re.match(r"^(-[efdszrwx])\s+(.+)$", expr)
        if m:
            flag, path = m.group(1), unquote(m.group(2))
            try:
                node = self.shell.resolve_path(path)
                if flag == "-e": return True
                if flag == "-f": return not node.is_dir
                if flag == "-d": return node.is_dir
                if flag == "-s": return node.size > 0
                if flag == "-z": return node.size == 0
                if flag in ("-r", "-w", "-x"): return True
            except FileNotFoundError:
                return False

        # -z (empty string)  -n (non-empty string)
        m = re.match(r"^(-z|-n)\s+(.*)$", expr)
        if m:
            flag, val = m.group(1), unquote(m.group(2))
            if flag == "-z": return len(val) == 0
            if flag == "-n": return len(val) > 0

        # boolean NOT
        if expr.startswith("! "):
            return not self._eval_test(expr[2:])

        # fallback: non-empty string = true
        return bool(unquote(expr))

    # ---- for loop ----

    def _exec_for(self, block: list[str]):
        header = block[0].strip()
        # for VAR in LIST; do  or  for VAR in LIST\ndo
        m = re.match(r"^for\s+(\w+)\s+in\s+(.*?)(?:\s*;\s*do)?\s*$", header)
        if not m:
            print(f"script: syntax error in for loop: {header}")
            return

        var = m.group(1)
        items_str = self._expand(m.group(2))

        # handle brace expansion  {1..5}
        items_str = self._brace_expand(items_str)
        # handle glob-like splits
        raw_items = shlex.split(items_str) if items_str.strip() else []

        items = []
        for token in raw_items:
            if "*" in token or "?" in token:
                # match against current directory children
                ext_pat = re.escape(token).replace(r"\*", ".*").replace(r"\?", ".")
                matched = sorted(
                    n.name for n in self.env.cwd.children.values()
                    if re.fullmatch(ext_pat, n.name) and not n.is_dir
                )
                if matched:
                    items.extend(matched)
                else:
                    items.append(token)  # no match → keep literal (bash behaviour)
            else:
                items.append(token)

        # collect loop body (between do … done)
        body = []
        in_body = False
        for l in block[1:]:
            ls = l.strip()
            if ls == "do":
                in_body = True
                continue
            if ls == "done":
                break
            if in_body:
                body.append(l)

        for item in items:
            self.env.vars[var] = item
            self._local_vars[var] = item
            self.run_lines(body)
            if self._break_flag:
                self._break_flag = False
                break
            self._continue_flag = False

    def _brace_expand(self, s: str) -> str:
        """Expand {1..5} or {a,b,c} style brace expressions."""
        m = re.search(r"\{(\d+)\.\.(\d+)\}", s)
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            step = 1 if end >= start else -1
            expanded = " ".join(str(i) for i in range(start, end + step, step))
            return s[:m.start()] + expanded + s[m.end():]

        m = re.search(r"\{([^{}]+)\}", s)
        if m:
            items = m.group(1).split(",")
            prefix = s[:m.start()]
            suffix = s[m.end():]
            return " ".join(prefix + i + suffix for i in items)

        return s

    # ---- while / until loop ----

    def _exec_while(self, block: list[str], invert: bool = False):
        header = block[0].strip()
        kw = "until" if invert else "while"
        m = re.match(rf"^{kw}\s+(.*?)(?:\s*;\s*do)?\s*$", header)
        if not m:
            print(f"script: syntax error in {kw} loop")
            return

        cond_str = m.group(1)
        body = []
        in_body = False
        for l in block[1:]:
            ls = l.strip()
            if ls == "do":
                in_body = True
                continue
            if ls == "done":
                break
            if in_body:
                body.append(l)

        max_iter = 10000  # safety
        iteration = 0
        while iteration < max_iter:
            cond_result = self._eval_condition(cond_str)
            should_run = (not cond_result) if invert else cond_result
            if not should_run:
                break
            self.run_lines(body)
            if self._break_flag:
                self._break_flag = False
                break
            self._continue_flag = False
            iteration += 1

    # ---- single line execution ----

    def _exec_line(self, line: str):
        line = line.strip()
        if not line or line.startswith("#"):
            return

        # output redirection  cmd > file  cmd >> file  cmd 2> file  cmd &> file
        redir_match = re.search(r"\s+(2>&1|&>>|&>|>>|2>|>)\s+(\S+)\s*$", line)
        if redir_match:
            redir_op = redir_match.group(1)
            redir_file = redir_match.group(2)
            cmd_part = line[:redir_match.start()]

            output = self._capture_line(cmd_part)

            try:
                dest_node = self._get_or_create_file(redir_file)
                if ">>" in redir_op:
                    dest_node.content += output
                else:
                    dest_node.content = output
            except Exception as e:
                print(f"script: redirection error: {e}")
            return

        # pipe  cmd1 | cmd2
        if "|" in line and "||" not in line:
            parts = line.split("|", 1)
            output = self._capture_line(parts[0].strip())
            self.shell._run_piped(parts[1].strip(), output or "")
            return

        # &&  ||
        if "&&" in line:
            for part in line.split("&&"):
                self._exec_line(part.strip())
                if self.env.last_exit_code != 0:
                    return
            return
        if "||" in line:
            parts = line.split("||", 1)
            self._exec_line(parts[0].strip())
            if self.env.last_exit_code != 0:
                self._exec_line(parts[1].strip())
            return

        # arithmetic assignment  let "x=1+2"  or  (( x++ ))
        m = re.match(r"^let\s+[\"']?(.+?)[\"']?$", line)
        if m:
            self._eval_arithmetic(m.group(1))
            return

        m = re.match(r"^\(\(\s*(.+?)\s*\)\)$", line)
        if m:
            self._eval_arithmetic(m.group(1))
            return

        # local VAR=val
        m = re.match(r"^local\s+(\w+)=(.*)", line)
        if m:
            k, v = m.group(1), self._expand(m.group(2))
            self._local_vars[k] = v
            self.env.vars[k] = v
            return

        # variable assignment  VAR=val  (no space around =)
        m = re.match(r"^([A-Za-z_]\w*)=(.*)", line)
        if m and " " not in m.group(1):
            k, v = m.group(1), self._expand(m.group(2))
            self.env.vars[k] = v
            self._local_vars[k] = v
            return

        # function call
        try:
            call_parts = shlex.split(self._expand(line))
        except Exception:
            call_parts = line.split()
        cmd_name = call_parts[0] if call_parts else ""
        call_args = call_parts[1:] if len(call_parts) > 1 else []

        if cmd_name in self._functions:
            fn_lines = self._functions[cmd_name]
            sub = ScriptInterpreter(self.shell)
            sub._functions = dict(self._functions)
            sub._local_vars = dict(self._local_vars)
            # inject positional args
            for idx, arg in enumerate(call_args, 1):
                sub._local_vars[str(idx)] = arg
            sub._local_vars["@"] = " ".join(call_args)
            sub._local_vars["#"] = str(len(call_args))
            sub.run_lines(fn_lines)
            self.env.last_exit_code = sub._return_value or 0
            return

        # delegate to shell
        self.shell.run(self._expand(line))

    def _capture_line(self, line: str) -> str:
        """Run a line, capture stdout, return as string."""
        line = self._expand(line)
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            self.shell.run(line)
        finally:
            sys.stdout = old
        return buf.getvalue()

    def _get_or_create_file(self, path: str) -> Node:
        """Resolve or create a file node for output redirection."""
        try:
            return self.shell.resolve_path(path)
        except FileNotFoundError:
            parent = self.shell.env.cwd
            name = path
            if "/" in path:
                head, name = path.rsplit("/", 1)
                parent = self.shell.resolve_path(head)
            node = Node(name, parent, is_dir=False, content="", owner=self.shell.env.user)
            parent.children[name] = node
            return node

    def _eval_arithmetic(self, expr: str):
        """Evaluate arithmetic expression, update variables."""
        expr = self._expand(expr)
        # inject current vars as ints where possible
        local = {}
        for k, v in {**self.env.vars, **self._local_vars}.items():
            try:
                local[k] = int(v)
            except (ValueError, TypeError):
                pass
        try:
            # handle x++ and x--
            expr = re.sub(r"(\w+)\+\+", r"\1 + 1", expr)
            expr = re.sub(r"(\w+)--", r"\1 - 1", expr)

            # assignment arithmetic: x = expr
            m = re.match(r"(\w+)\s*=\s*(.+)", expr)
            if m:
                var, val_expr = m.group(1), m.group(2)
                result = int(eval(val_expr, {"__builtins__": {}}, local))
                self.env.vars[var] = str(result)
                self._local_vars[var] = str(result)
                return result
            else:
                return int(eval(expr, {"__builtins__": {}}, local))
        except Exception:
            return 0

    def _expand(self, text: str) -> str:
        """Expand variables, arithmetic, and command substitutions."""
        if not text:
            return text

        # arithmetic  $(( expr ))
        text = re.sub(
            r"\$\(\(\s*(.*?)\s*\)\)",
            lambda m: str(self._eval_arithmetic(m.group(1))),
            text
        )

        # command substitution  $( cmd )
        text = re.sub(
            r"\$\(([^)]+)\)",
            lambda m: self._capture_line(m.group(1)).strip(),
            text
        )

        # ${VAR:-default}
        text = re.sub(
            r"\$\{(\w+):-([^}]*)\}",
            lambda m: self.env.vars.get(m.group(1)) or self._local_vars.get(m.group(1)) or m.group(2),
            text
        )

        # ${VAR}
        text = re.sub(
            r"\$\{(\w+)\}",
            lambda m: str(self.env.vars.get(m.group(1), self._local_vars.get(m.group(1), ""))),
            text
        )

        # $VAR  (word boundary)
        def expand_var(m):
            name = m.group(1)
            if name == "?":
                return str(self.env.last_exit_code)
            # positional / special params live in _local_vars
            if name in self._local_vars:
                return str(self._local_vars[name])
            return str(self.env.vars.get(name, ""))

        text = re.sub(r"\$([A-Za-z_?]\w*|\d+)", expand_var, text)

        # strip surrounding quotes
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
            text = text[1:-1]

        return text


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
            Command("ls",       "ls [-la] [path]",            "list directory contents",         self.ls),
            Command("cd",       "cd <path>",                  "change directory",                self.cd),
            Command("pwd",      "pwd",                        "print working directory",         self.pwd),
            Command("cat",      "cat <file>",                 "print file contents",             self.cat),
            Command("nano",     "nano <file>",                "edit a file interactively",       self.nano),
            Command("mkdir",    "mkdir [-p] <dir>",           "create a directory",              self.mkdir),
            Command("touch",    "touch <file>",               "create an empty file",            self.touch),
            Command("rm",       "rm [-r] <path>",             "remove file or directory",        self.rm),
            Command("cp",       "cp [-r] <src> <dst>",        "copy a file or directory",        self.cp),
            Command("mv",       "mv <src> <dst>",             "move or rename a file",           self.mv),
            Command("grep",     "grep [-n|-r|-v|-i] <p> <f>", "search pattern in file",          self.grep),
            Command("find",     "find <path> [-name <pat>]",  "find files by name",              self.find),
            Command("echo",     "echo [-n] <text>",           "print text",                      self.echo),
            Command("printf",   "printf <fmt> [args]",        "formatted print",                 self.printf),
            Command("export",   "export [KEY=val]",           "set or list env variables",       self.export),
            Command("unset",    "unset <var>",                "unset an env variable",           self.unset),
            Command("chmod",    "chmod <mode> <file>",        "change file permissions",         self.chmod),
            Command("chown",    "chown <owner> <file>",       "change file owner",               self.chown),
            Command("head",     "head [-n N] <file>",         "print first N lines",             self.head),
            Command("tail",     "tail [-n N] <file>",         "print last N lines",              self.tail),
            Command("wc",       "wc [-lwc] <file>",           "word/line/char count",            self.wc),
            Command("sort",     "sort [-r|-n|-u] <file>",     "sort lines of a file",            self.sort),
            Command("uniq",     "uniq [-c] <file>",           "filter/count duplicate lines",    self.uniq),
            Command("cut",      "cut -d <d> -f <n> <file>",  "cut fields from lines",           self.cut),
            Command("tr",       "tr <set1> <set2>",           "translate characters (piped)",    self.tr),
            Command("tee",      "tee <file>",                 "pipe to file and stdout",         self.tee),
            Command("diff",     "diff <file1> <file2>",       "compare two files",               self.diff),
            Command("file",     "file <path>",                "determine file type",             self.file_cmd),
            Command("stat",     "stat <path>",                "file status info",                self.stat),
            Command("du",       "du [-sh] <path>",            "disk usage",                      self.du),
            Command("df",       "df [-h]",                    "disk free space",                 self.df),
            # text utilities
            Command("which",    "which <cmd>",                "locate a command",                self.which),
            Command("whoami",   "whoami",                     "print current user",              self.whoami),
            Command("id",       "id",                         "print user/group ids",            self.id_cmd),
            Command("hostname", "hostname",                   "print hostname",                  self.hostname_cmd),
            Command("uname",    "uname [-a]",                 "system information",              self.uname),
            Command("uptime",   "uptime",                     "system uptime",                   self.uptime_cmd),
            Command("date",     "date",                       "print current date/time",         self.date_cmd),
            Command("history",  "history",                    "show command history",            self.history_cmd),
            Command("read",     "read <var>",                 "read input into variable",        self.read),
            Command("sleep",    "sleep <seconds>",            "sleep for N seconds",             self.sleep_cmd),
            Command("true",     "true",                       "exit with success",               self.true_cmd),
            Command("false",    "false",                      "exit with failure",               self.false_cmd),
            Command("test",     "test <expr>",                "evaluate expression",             self.test_cmd),
            Command("env",      "env",                        "print all environment variables", self.env_cmd),
            Command("printenv", "printenv [VAR]",             "print environment variable",      self.printenv),
            Command("xargs",    "xargs <cmd>",                "build commands from stdin",       self.xargs),
            # process
            Command("ps",       "ps [-aux]",                  "list processes",                  self.ps),
            Command("kill",     "kill [-9] <pid>",            "send signal to process",          self.kill_cmd),
            Command("jobs",     "jobs",                       "list background jobs",            self.jobs_cmd),
            # network
            Command("ping",     "ping [-c N] <ip>",           "check if host is alive",          self.ping),
            Command("scan",     "scan [prefix]",              "scan the network",                self.scan),
            Command("connect",  "connect <ip>",               "connect to a host",               self.connect),
            Command("ifconfig", "ifconfig",                   "network interface info",          self.ifconfig),
            Command("ip",       "ip [addr|route]",            "network info (modern)",           self.ip_cmd),
            Command("netstat",  "netstat [-tlnp]",            "network connections",             self.netstat),
            Command("curl",     "curl [-s|-o] <url>",         "transfer data from a URL",        self.curl),
            Command("wget",     "wget <url>",                 "download a file",                 self.wget),
            Command("traceroute","traceroute <ip>",           "trace network path",              self.traceroute),
            Command("nslookup", "nslookup <host>",            "DNS lookup",                      self.nslookup),
            # scripting / shell
            Command("run",      "run <file.sh>",              "execute a shell script",          self.run_script),
            Command("source",   "source <file>",              "source a script in current shell",self.source_cmd),
            Command("alias",    "alias [name=cmd]",           "define or list aliases",          self.alias_cmd),
            Command("type",     "type <cmd>",                 "describe a command",              self.type_cmd),
            # meta
            Command("help",     "help [command]",             "show this help",                  self.help),
            Command("man",      "man <command>",              "show manual for a command",       self.man_cmd),
            Command("clear",    "clear",                      "clear screen",                    self.clear),
            Command("exit",     "exit [N]",                   "exit the shell",                  self.exit_cmd),
        ]:
            self.commands[cmd.name] = cmd

        self._aliases: dict[str, str] = {}
        self._processes = [
            {"pid": 1, "user": "root", "cpu": 0.0, "mem": 0.1, "cmd": "init"},
            {"pid": 423, "user": "root", "cpu": 0.0, "mem": 0.3, "cmd": "sshd"},
            {"pid": 512, "user": "root", "cpu": 0.0, "mem": 0.2, "cmd": "cron"},
            {"pid": 1001, "user": "student", "cpu": 0.1, "mem": 0.5, "cmd": "bash"},
        ]

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

        # expand aliases
        first_word = line.split()[0]
        if first_word in self._aliases:
            line = self._aliases[first_word] + line[len(first_word):]

        # ---- operator splitting: handle &&  ||  |  ----------------------

        # pipe  a | b  (only two-command pipes)
        if "|" in line and "||" not in line:
            left, right = line.split("|", 1)
            output = self._run_single(left.strip(), capture=True)
            self._run_piped(right.strip(), output or "")
            return

        # logical AND (split before pipe/redir so each segment is handled alone)
        if "&&" in line:
            parts = line.split("&&")
            for p in parts:
                self.run(p.strip())
                if self.env.last_exit_code != 0:
                    break
            return

        # logical OR
        if "||" in line:
            parts = line.split("||", 1)
            self.run(parts[0].strip())
            if self.env.last_exit_code != 0:
                self.run(parts[1].strip())
            return

        if "|" in line and "||" not in line:
            segments = line.split("|")
            # run first segment, capture output
            output = self._run_single(segments[0].strip(), capture=True) or ""
            # pipe through middle and last segments
            for seg in segments[1:]:
                buf = io.StringIO()
                old = sys.stdout
                sys.stdout = buf
                try:
                    self._run_piped(seg.strip(), output)
                finally:
                    sys.stdout = old
                output = buf.getvalue()
            print(output, end="")
            return


        # output redirection at the shell level
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
                node.mtime = datetime.datetime.now().strftime("%b %d %H:%M")
            except Exception as e:
                print(f"bash: {e}")
            return

        self._run_single(line, capture=_capture)

    def _run_single(self, line: str, capture: bool = False) -> Optional[str]:
        """Run a single command with no operators."""
        line = line.strip()
        if not line or line.startswith("#"):
            return

        # expand vars first
        line = self._expand_vars(line)

        # variable assignment  e.g.  TARGET=192.168.0.25
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
                return

        if line.startswith("./"):
            return self._dispatch("run", [line[2:]], capture)

        try:
            parts = shlex.split(line)
        except Exception:
            print(f"bash: parse error near '{line}'")
            self.env.last_exit_code = 1
            return

        if not parts:
            return

        cmd, args = parts[0], parts[1:]

        if cmd in self.commands:
            if capture:
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
            self.env.last_exit_code = 127

    def _dispatch(self, cmd, args, capture):
        if capture:
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

            flags   = [a for a in args if a.startswith("-")]
            targets = [a for a in args if not a.startswith("-")]
            pattern  = targets[0] if targets else ""
            invert   = "-v" in flags
            insensitive = "-i" in flags
            show_num = "-n" in flags
            for i, ln in enumerate(stdin_text.splitlines(), 1):
                haystack = ln.lower() if insensitive else ln
                needle   = pattern.lower() if insensitive else pattern
                match = needle in haystack
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
                except Exception as e:
                    print(f"tee: {e}")
            print(stdin_text, end="")
        elif cmd == "xargs":
            if args:
                target_cmd = args[0]
                items = stdin_text.split()
                for item in items:
                    self.run(f"{target_cmd} {item}")
        elif cmd == "cut":
            self._pipe_cut(stdin_text, args)
        elif cmd == "cat":
            print(stdin_text, end="")
        elif cmd in self.commands:
            self.commands[cmd].fn(args)
        else:
            print(f"bash: command not found: {cmd}")

    def _pipe_sort(self, text, args):
        flags = "".join(a.lstrip("-") for a in args if a.startswith("-"))
        lines = text.splitlines()
        reverse = "r" in flags
        numeric = "n" in flags
        unique  = "u" in flags
        key_fn  = (lambda x: int(x) if x.isdigit() else 0) if numeric else str
        if unique:
            seen = set()
            deduped = []
            for l in lines:
                if l not in seen:
                    seen.add(l)
                    deduped.append(l)
            lines = deduped
        lines.sort(key=key_fn, reverse=reverse)
        print("\n".join(lines))

    def _pipe_uniq(self, text, args):
        count = "-c" in args
        lines = text.splitlines()
        result = []
        i = 0
        while i < len(lines):
            j = i
            while j < len(lines) and lines[j] == lines[i]:
                j += 1
            if count:
                result.append(f"  {j - i:4}  {lines[i]}")
            else:
                result.append(lines[i])
            i = j
        print("\n".join(result))

    def _pipe_tr(self, text, args):
        if len(args) < 2:
            print(text, end="")
            return
        table = str.maketrans(args[0], args[1])
        print(text.translate(table), end="")

    def _pipe_cut(self, text, args):
        delim = "\t"
        fields = []
        i = 0
        while i < len(args):
            if args[i] == "-d" and i + 1 < len(args):
                delim = args[i + 1]
                i += 2
            elif args[i] == "-f" and i + 1 < len(args):
                try:
                    fields = [int(f) - 1 for f in args[i + 1].split(",")]
                except ValueError:
                    pass
                i += 2
            else:
                i += 1
        for line in text.splitlines():
            parts = line.split(delim)
            selected = [parts[f] for f in fields if f < len(parts)]
            print(delim.join(selected))

    def _expand_vars(self, text: str) -> str:
        # $?
        text = re.sub(r"\$\?", str(self.env.last_exit_code), text)

        # ${VAR:-default}
        text = re.sub(
            r"\$\{(\w+):-([^}]*)\}",
            lambda m: self.env.vars.get(m.group(1), m.group(2)),
            text
        )
        # ${VAR}
        text = re.sub(
            r"\$\{(\w+)\}",
            lambda m: self.env.vars.get(m.group(1), ""),
            text
        )
        # $VAR
        for k, v in sorted(self.env.vars.items(), key=lambda x: -len(x[0])):
            text = re.sub(rf"\${k}\b", v, text)

        # $(( expr )) – basic arithmetic
        text = re.sub(
            r"\$\(\(\s*(.*?)\s*\)\)",
            lambda m: str(self._eval_arith(m.group(1))),
            text
        )
        # $( cmd )
        text = re.sub(
            r"\$\(([^)]+)\)",
            lambda m: (self._run_single(m.group(1).strip(), capture=True) or "").strip(),
            text
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


    # =====================================================
    # PATH HELPERS
    # =====================================================
    def resolve_path(self, path: str) -> Node:
        # if path in ("~", f"/home/{self.env.user}"):
        #     return self.env.root.children.get("home", self.env.root)
        # Note: in this virtual FS, files live directly under /home (not /home/student).
        home_path = self.env.vars.get("HOME", "/home/student")
        # Normalise HOME to the actual node that exists
        # Walk from root to find the deepest existing node matching HOME
        def _home_node():
            parts = home_path.strip("/").split("/")
            node = self.env.root
            for p in parts:
                if p in getattr(node, "children", {}):
                    node = node.children[p]
                else:
                    # parent dir exists but leaf doesn't – return parent
                    break
            return node

        if path.startswith("~/"):
            # replace ~ with the actual home node path
            home_node = _home_node()
            home_abs  = self.get_path(home_node)
            path = home_abs.rstrip("/") + "/" + path[2:]
        elif path == "~":
            return _home_node()

        if not path or path == ".":
            return self.env.cwd

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
        # -a flag would show hidden files;
        show_hidden = any("a" in f for f in flags)

        try:
            node = self.resolve_path(targets[0]) if targets else self.env.cwd
        except FileNotFoundError as e:
            print(f"ls: cannot access '{targets[0] if targets else ''}': {e}")
            self.env.last_exit_code = 1
            return

        self.env.last_exit_code = 0

        if not node.is_dir:
            if long:
                self._ls_long_line(node)
            else:
                print(node.name)
            return

        entries = sorted(node.children.values(), key=lambda n: n.name)
        if not show_hidden:
            entries = [n for n in entries if not n.name.startswith(".")]
        if not entries:
            # print statement could be removed if wanted
            print("(empty)")
            return

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
        mtime   = node.mtime

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
            print(f"bash: cd: {e}")
            self.env.last_exit_code = 1
            return
        if not node.is_dir:
            print(f"bash: cd: not a directory: {args[0]}")
            self.env.last_exit_code = 1
            return
        self.env.vars["OLDPWD"] = self.get_path(self.env.cwd)
        self.env.cwd = node
        self.env.last_exit_code = 0

    def pwd(self, args):
        print(self.get_path(self.env.cwd))
        self.env.last_exit_code = 0

    def cat(self, args):
        if not args:
            print("usage: cat <file>"); return
        for path in args:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError as e:
                print(f"cat: {path}: No such file or directory")
                self.env.last_exit_code = 1
                continue
            if node.is_dir:
                print(f"cat: {path}: is a directory")
                self.env.last_exit_code = 1
            else:
                print(node.content, end="" if node.content.endswith("\n") else "\n")
                self.env.last_exit_code = 0

    def mkdir(self, args):
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
                    parent = self.env.cwd
                    name   = path
                    if "/" in path:
                        head, name = path.rsplit("/", 1)
                        parent = self.resolve_path(head)
                    if name in parent.children:
                        print(f"mkdir: cannot create directory '{path}': File exists")
                        self.env.last_exit_code = 1
                        continue
                    new_node = Node(name, parent, is_dir=True, owner=self.env.user)
                    parent.children[name] = new_node
                self.env.last_exit_code = 0
            except FileNotFoundError as e:
                print(f"mkdir: {e}")
                self.env.last_exit_code = 1

    def _mkdir_p(self, path: str):
        node = self.env.root if path.startswith("/") else self.env.cwd
        parts = path.lstrip("/").split("/") if path.startswith("/") else path.split("/")
        for p in parts:
            if not p or p == ".":
                continue
            if p == "..":
                if node.parent:
                    node = node.parent
                continue
            if p not in node.children:
                new = Node(p, node, is_dir=True, owner=self.env.user)
                node.children[p] = new
            node = node.children[p]

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
                self.env.last_exit_code = 0
            except FileNotFoundError as e:
                print(f"touch: {e}")
                self.env.last_exit_code = 1

    def rm(self, args):
        if not args:
            print("usage: rm [-r] <path>"); return
        flags   = {a for a in args if a.startswith("-")}
        targets = [a for a in args if not a.startswith("-")]
        recursive = "-r" in flags or "-rf" in flags or "-fr" in flags
        force     = any("f" in f for f in flags)

        for path in targets:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError as e:
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

    def cp(self, args):
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        if len(targets) < 2:
            print("usage: cp [-r] <src> <dst>");return
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

    def _cp_node(self, src: Node, dest_parent: Node, dest_name: str):
        real_mtime = datetime.datetime.now().strftime("%b %d %H:%M")
        if src.is_dir:
            new_dir = Node(dest_name, dest_parent, is_dir=True, owner=self.env.user)
            new_dir.mtime = real_mtime
            dest_parent.children[dest_name] = new_dir
            for child in src.children.values():
                self._cp_node(child, new_dir, child.name)
        else:
            new_node = Node(
                dest_name, dest_parent, is_dir=False,
                content=src.content, permissions=src.permissions, owner=self.env.user
            )
            new_node.mtime = real_mtime
            dest_parent.children[dest_name] = new_node

    def mv(self, args):
        if len(args) < 2:
            print("usage: mv <src> <dst>"); return
        try:
            src = self.resolve_path(args[0])
        except FileNotFoundError as e:
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
        self.env.last_exit_code = 0

    def grep(self, args):
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
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
        paths = targets[1:] if len(targets) > 1 else ["."]

        matches = []
        for path in paths:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError:
                print(f"grep: {path}: No such file or directory")
                continue
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

    def _grep_file(self, node, pattern, flags, label=None):
        show_num = "-n" in flags
        invert = "-v" in flags
        insensitive = "-i" in flags
        results = []
        for i, ln in enumerate(node.content.splitlines(), 1):
            haystack = ln.lower() if insensitive else ln
            needle = pattern.lower() if insensitive else pattern
            match = needle in haystack
            if invert:
                match = not match
            if match:
                prefix = (f"{label}:" if label else "") + (f"{i}:" if show_num else "")
                results.append(prefix + ln)
        return results

    def _grep_dir(self, node, pattern, flags, prefix):
        results = []
        for child in node.children.values():
            child_path = f"{prefix}/{child.name}"
            if child.is_dir:
                results.extend(self._grep_dir(child, pattern, flags, child_path))
            else:
                results.extend(self._grep_file(child, pattern, flags, child_path))
        return results

    def find(self, args):
        if not args:
            args = ["."]
        path = args[0]
        name_pat = None
        type_pat = None
        i = 1
        while i < len(args):
            if args[i] == "-name" and i + 1 < len(args):
                name_pat = args[i + 1]
                i += 2
            elif args[i] == "-type" and i + 1 < len(args):
                type_pat = args[i + 1]  # f or d
                i += 2
            else:
                i += 1
        try:
            start = self.resolve_path(path)
        except FileNotFoundError as e:
            print(f"find: '{path}': No such file or directory")
            self.env.last_exit_code = 1
            return
        results = []
        self._find_recursive(start, path, name_pat, type_pat, results)
        for r in results:
            print(r)
        self.env.last_exit_code = 0

    def _find_recursive(self, node, path, name_pat, type_pat, results):
        def matches(n, p):
            if name_pat:
                # glob-like: * wildcard
                pat = re.escape(name_pat).replace(r"\*", ".*").replace(r"\?", ".")
                if not re.fullmatch(pat, n.name):
                    return False
            if type_pat:
                if type_pat == "f" and n.is_dir:
                    return False
                if type_pat == "d" and not n.is_dir:
                    return False
            return True

        if matches(node, path):
            results.append(path)

        if node.is_dir:
            for child in node.children.values():
                child_path = f"{path}/{child.name}"
                self._find_recursive(child, child_path, name_pat, type_pat, results)

    def echo(self, args):
        # handle -n flag (no trailing newline)
        no_newline = args and args[0] == "-n"
        if no_newline:
            args = args[1:]
        text = " ".join(args)
        if no_newline:
            print(text, end="")
        else:
            print(text)
        self.env.last_exit_code = 0

    def printf(self, args):
        if not args:
            print("usage: printf <format> [args]"); return
        fmt = args[0]
        rest = args[1:]
        # basic format specifiers
        try:
            # Count how many arguments the format string consumes per pass
            # (one per %s / %d / %f specifier, ignoring %% which consumes none)
            specifiers_per_pass = len(re.findall(r"%[sdif]", fmt))
            if specifiers_per_pass == 0 or not rest:
                # No specifiers or no args – run exactly once
                passes = [(fmt, [])]
            else:
                # Group rest into chunks of specifiers_per_pass
                passes = []
                for start in range(0, max(len(rest), 1), specifiers_per_pass):
                    passes.append((fmt, rest[start:start + specifiers_per_pass]))

            for cur_fmt, cur_args in passes:
                out = ""
                i = 0
                arg_i = 0
                while i < len(cur_fmt):
                    if cur_fmt[i] == "%" and i + 1 < len(cur_fmt):
                        spec = cur_fmt[i + 1]
                        val = cur_args[arg_i] if arg_i < len(cur_args) else ""
                        if spec == "s":
                            out += str(val)
                        elif spec in ("d", "i"):
                            out += str(int(val)) if val else "0"
                        elif spec == "f":
                            out += f"{float(val):.6f}" if val else "0.000000"
                        elif spec == "%":
                            out += "%"
                        elif spec == "n":
                            out += "\n"
                        else:
                            out += "%" + spec
                        if spec != "%":
                            arg_i += 1
                        i += 2
                    elif cur_fmt[i] == "\\" and i + 1 < len(cur_fmt):
                        esc = cur_fmt[i + 1]
                        if esc == "n":
                            out += "\n"
                        elif esc == "t":
                            out += "\t"
                        elif esc == "\\":
                            out += "\\"
                        else:
                            out += "\\" + esc
                        i += 2
                    else:
                        out += cur_fmt[i]
                        i += 1
                print(out, end="")
        except Exception as e:
            print(f"printf: {e}")
        self.env.last_exit_code = 0

    def export(self, args):
        if not args:
            for k, v in self.env.vars.items():
                print(f"declare -x {k}=\"{v}\"")
            return
        for arg in args:
            if "=" in arg:
                k, _, v = arg.partition("=")
                self.env.vars[k.strip()] = v.strip()
            else:
                # export existing var (already in vars, just a no-op for visibility)
                pass
        self.env.last_exit_code = 0

    def unset(self, args):
        for var in args:
            self.env.vars.pop(var, None)
        self.env.last_exit_code = 0

    def read(self, args):
        if not args:
            print("usage: read <var>"); return
        prompt = ""
        var = args[-1]
        if "-p" in args:
            idx = args.index("-p")
            if idx + 1 < len(args):
                prompt = args[idx+1]
                var = args[-1]
        try:
            value = input(prompt)
        except EOFError:
            value = ""
        self.env.vars[var] = value
        self.env.last_exit_code = 0

    def sort(self, args):
        flags = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: sort [-rnu] <file>");
            return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError as e:
            print(f"sort: {e}");
            return
        if node.is_dir:
            print("sort: Is a directory");
            return
        self._pipe_sort(node.content, flags)

    def uniq(self, args):
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: uniq [-c] <file>");
            return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError as e:
            print(f"uniq: {e}");
            return
        self._pipe_uniq(node.content, args)

    def cut(self, args):
        targets = [a for a in args if not a.startswith("-") and args[args.index(a) - 1] not in ("-d", "-f")]
        content = ""
        for t in targets:
            try:
                node = self.resolve_path(t)
                content = node.content
            except FileNotFoundError as e:
                print(f"cut: {e}");
                return
        self._pipe_cut(content, args)

    def tr(self, args):
        print("usage: echo 'text' | tr <set1> <set2>")

    def tee(self, args):
        print("usage: <cmd> | tee <file>")

    def diff(self, args):
        if len(args) < 2:
            print("usage: diff <file1> <file2>");
            return
        try:
            a = self.resolve_path(args[0]).content.splitlines()
            b = self.resolve_path(args[1]).content.splitlines()
        except FileNotFoundError as e:
            print(f"diff: {e}");
            return

        i = j = 0
        while i < len(a) or j < len(b):
            if i < len(a) and j < len(b):
                if a[i] == b[j]:
                    i += 1;
                    j += 1
                else:
                    print(f"< {a[i]}");
                    i += 1
                    print(f"> {b[j]}");
                    j += 1
            elif i < len(a):
                print(f"< {a[i]}");
                i += 1
            else:
                print(f"> {b[j]}");
                j += 1
        self.env.last_exit_code = 0

    def file_cmd(self, args):
        if not args:
            print("usage: file <path>");
            return
        for path in args:
            try:
                node = self.resolve_path(path)
            except FileNotFoundError:
                print(f"file: {path}: No such file or directory");
                continue
            if node.is_dir:
                print(f"{path}: directory")
            else:
                ext = path.rsplit(".", 1)[-1] if "." in path else ""
                types = {
                    "py": "Python script, ASCII text executable",
                    "sh": "Bourne-Again shell script, ASCII text executable",
                    "md": "Markdown text, ASCII text",
                    "txt": "ASCII text",
                    "json": "JSON data",
                    "html": "HTML document, ASCII text",
                }
                print(f"{path}: {types.get(ext, 'ASCII text')}")

    def stat(self, args):
        if not args:
            print("usage: stat <path>");
            return
        try:
            node = self.resolve_path(args[0])
        except FileNotFoundError as e:
            print(f"stat: cannot stat '{args[0]}': No such file or directory");
            return
        kind = "directory" if node.is_dir else "regular file"
        perm = node.permission_bits()
        print(f"  File: {args[0]}")
        print(f"  Size: {node.size}  \tBlocks: {max(1, node.size // 512)}  \tIO Block: 4096  {kind}")
        print(f"Device: sda1  Inode: {abs(hash(node.name)) % 99999}  Links: 1")
        print(
            f"Access: ({perm:04o}/{('d' if node.is_dir else '-')}{node.permissions})  Uid: (1000/{node.owner})  Gid: (1000/{node.owner})")
        print(f"Modify: 2025-04-10 12:34:00.000000000 +0000")
        self.env.last_exit_code = 0

    def du(self, args):
        flags = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        human = "-h" in flags or (len(flags) > 0 and any("h" in f for f in flags))
        summary = "-s" in flags or (len(flags) > 0 and any("s" in f for f in flags))
        path = targets[0] if targets else "."
        try:
            node = self.resolve_path(path)
        except FileNotFoundError as e:
            print(f"du: {e}"); return
        total = self._du_size(node)
        if human:
            size_str = self._human_size(total)
        else:
            size_str = str(max(1, (total + 1023) // 1024))
        print(f"{size_str}\t{path}")

    def _du_size(self, node):
        if not node.is_dir:
            return node.size
        return sum(self._du_size(c) for c in node.children.values()) + 4096

    def _human_size(self, size):
        for unit in ["B", "K", "M", "G", "T"]:
            if size < 1024:
                return f"{size:.0f}{unit}"
            size /= 1024
        return f"{size:.0f}P"

    def df(self, args):
        human = "-h" in args
        if human:
            print(f"{'Filesystem':<20}  {'Size':>6}  {'Used':>6}  {'Avail':>6}  {'Use%':>5}  Mounted on")
            print(f"{'sda1':<20}  {'20G':>6}  {'4.2G':>6}  {'15G':>6}  {'21%':>5}  /")
            print(f"{'tmpfs':<20}  {'512M':>6}  {'12K':>6}  {'512M':>6}  {'1%':>5}  /tmp")
        else:
            print(f"{'Filesystem':<20}  {'1K-blocks':>10}  {'Used':>10}  {'Available':>10}  {'Use%':>5}  Mounted on")
            print(f"{'sda1':<20}  {20971520:>10}  {4404224:>10}  {15728640:>10}  {'21%':>5}  /")

        print("Just simulation no real numbers!")

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
            print(f"chmod: cannot access '{path}': No such file or directory"); return

        if re.fullmatch(r"[0-7]{3}", mode_str):
            p = ""
            for digit in mode_str:
                d = int(digit)
                p += ("r" if d & 4 else "-")
                p += ("w" if d & 2 else "-")
                p += ("x" if d & 1 else "-")
            node.permissions = p
            self.env.last_exit_code = 0
            return

        if re.fullmatch(r"[0-7]{3}", mode_str):
            p = ""
            for digit in mode_str:
                d = int(digit)
                p += ("r" if d & 4 else "-")
                p += ("w" if d & 2 else "-")
                p += ("x" if d & 1 else "-")
            node.permissions = p
            self.env.last_exit_code = 0
            return

        m = re.fullmatch(r"([ugoa]*)([+\-=])([rwx]+)", mode_str)
        if not m:
            print(f"chmod: invalid mode: {mode_str}");
            return

        who, op, perms = m.group(1), m.group(2), m.group(3)
        if not who or who == "a":
            who = "ugo"

        p = list(node.permissions)
        who_map = {"u": (0, 1, 2), "g": (3, 4, 5), "o": (6, 7, 8)}
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

        node.permissions = "".join(p)
        self.env.last_exit_code = 0

    def chown(self, args):
        if len(args) < 2:
            print("usage: chown <owner> <file>"); return
        owner, path = args[0], args[1]
        try:
            node = self.resolve_path(path)
            node.owner = owner.split(":")[0]
            self.env.last_exit_code = 0
        except FileNotFoundError:
            print(f"chown: cannot access '{path}': No such file or directory")
            self.env.last_exit_code = 1

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
        except FileNotFoundError:
            print(f"head: cannot open '{targets[0]}': No such file or directory"); return
        if node.is_dir:
            print("head: is a directory"); return
        print("\n".join(node.content.splitlines()[:n]))
        self.env.last_exit_code = 0

    def tail(self, args):
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

    def wc(self, args):
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: wc [-lwc] <file>");
            return
        try:
            node = self.resolve_path(targets[0])
        except FileNotFoundError:
            print(f"wc: {targets[0]}: No such file or directory");
            return
        if node.is_dir:
            print("wc: Is a directory");
            return
        self._wc_text(node.content, args, targets[0])
        self.env.last_exit_code = 0

    def _wc_text(self, text, flags_args, label=""):
        lines = text.splitlines()
        words = text.split()
        chars = len(text)
        flags = [a for a in flags_args if a.startswith("-")]
        joined = "".join(flags)
        if not flags or not (set(joined) & {"l", "w", "c"}):
            print(f"  {len(lines):4}  {len(words):4}  {chars:4}  {label}")
        else:
            parts = []
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
                print(f"which: no {cmd} in ({self.env.vars.get('PATH', '/usr/bin')})")
        self.env.last_exit_code = 0

    def whoami(self, args):
        print(self.env.user)
        self.env.last_exit_code = 0

    def id_cmd(self, args):
        print(f"uid=1000({self.env.user}) gid=1000({self.env.user}) groups=1000({self.env.user}),27(sudo),100(users)")
        self.env.last_exit_code = 0

    def hostname_cmd(self, args):
        print(self.env.hostname)
        self.env.last_exit_code = 0

    def uname(self, args):
        if "-a" in args:
            print(
                f"Linux {self.env.hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux")
        elif "-r" in args:
            print("5.15.0-91-generic")
        elif "-m" in args:
            print("x86_64")
        else:
            print("Linux")
        self.env.last_exit_code = 0

    def uptime_cmd(self, args):
        print(" 09:45:02 up 2 days,  3:22,  1 user,  load average: 0.15, 0.10, 0.08")
        self.env.last_exit_code = 0

    def date_cmd(self, args):
        import datetime
        now = datetime.datetime.now()
        print(now.strftime("%a %b %d %H:%M:%S %Z %Y"))
        self.env.last_exit_code = 0

    def history_cmd(self, args):
        n = int(args[0]) if args and args[0].isdigit() else len(self._history)
        for i, entry in enumerate(self._history[-n:], max(1, len(self._history) - n + 1)):
            print(f"  {i:4}  {entry}")
        self.env.last_exit_code = 0

    def clear(self, args):
        print("\033[2J\033[H", end="")

    def exit_cmd(self, args):
        code = int(args[0]) if args and args[0].isdigit() else 0
        self.env.last_exit_code = code
        raise SystemExit(code)

    def sleep_cmd(self, args):
        if not args:
            print("usage: sleep <seconds>");
            return
        try:
            t = float(args[0])
            time.sleep(min(t, 5))  # cap at 5s for UX
        except ValueError:
            print(f"sleep: invalid time interval '{args[0]}'")
        self.env.last_exit_code = 0

    def true_cmd(self, args):
        self.env.last_exit_code = 0

    def false_cmd(self, args):
        self.env.last_exit_code = 1

    def test_cmd(self, args):
        # create a temporary ScriptInterpreter just to evaluate
        si = ScriptInterpreter(self)
        expr = " ".join(args)
        result = si._eval_test(expr)
        self.env.last_exit_code = 0 if result else 1

    def env_cmd(self, args):
        for k, v in sorted(self.env.vars.items()):
            print(f"{k}={v}")
        self.env.last_exit_code = 0

    def printenv(self, args):
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

    def xargs(self, args):
        print("usage: <cmd> | xargs <target_cmd>")

    def alias_cmd(self, args):
        if not args:
            for name, val in self._aliases.items():
                print(f"alias {name}='{val}'")
            return
        for arg in args:
            if "=" in arg:
                name, _, cmd = arg.partition("=")
                self._aliases[name] = cmd.strip("'\"")
            else:
                if arg in self._aliases:
                    print(f"alias {arg}='{self._aliases[arg]}'")
                else:
                    print(f"bash: alias: {arg}: not found")
        self.env.last_exit_code = 0

    def type_cmd(self, args):
        if not args:
            print("usage: type <cmd>");
            return
        for cmd in args:
            if cmd in self.commands:
                print(f"{cmd} is a shell builtin")
            elif cmd in self._aliases:
                print(f"{cmd} is aliased to '{self._aliases[cmd]}'")
            else:
                print(f"bash: type: {cmd}: not found")
        self.env.last_exit_code = 0

    # =====================================================
    # PROCESS COMMANDS
    # =====================================================
    def ps(self, args):
        # synthetic process list
        procs = list(self._processes)
        # add some noise
        procs.append({"pid": random.randint(1002, 1100), "user": self.env.user, "cpu": 0.0, "mem": 0.2, "cmd": "ps"})
        show_all = any("a" in a for a in args if a.startswith("-"))

        print(f"{'PID':>7}  {'USER':<10}  {'%CPU':>5}  {'%MEM':>5}  {'COMMAND'}")
        for p in procs:
            if not show_all and p["user"] != self.env.user and p["user"] != "root":
                continue
            print(f"{p['pid']:>7}  {p['user']:<10}  {p['cpu']:>5.1f}  {p['mem']:>5.1f}  {p['cmd']}")
        self.env.last_exit_code = 0

    def kill_cmd(self, args):
        if not args:
            print("usage: kill [-9] <pid>");
            return
        flags = [a for a in args if a.startswith("-")]
        pids = [a for a in args if not a.startswith("-")]
        sig = 9 if "-9" in flags else 15
        for pid_str in pids:
            try:
                pid = int(pid_str)
                # find process
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

    def jobs_cmd(self, args):
        print("[1]+  Running    sleep 100 &")  # fake background job
        self.env.last_exit_code = 0

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
                show_buffer(); continue

            # ---- insert before line  :i N <text> ----
            m = re.fullmatch(r":i\s+(\d+)\s+(.*)", raw.strip(), re.DOTALL)
            if m:
                idx  = int(m.group(1)) - 1
                text = m.group(2)
                lines.insert(max(0, idx), text)
                print(f"  inserted before line {idx+1}")
                show_buffer(); continue

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
                show_buffer(); continue

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
                show_buffer(); continue

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

        # parse -c <count> flag
        count = 4
        targets = []
        i = 0
        while i < len(args):
            if args[i] == "-c" and i + 1 < len(args):
                try:
                    count = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
            else:
                targets.append(args[i])
                i += 1

        if not targets:
            print("usage: ping [-c N] <ip>"); return

        ip = targets[0]

        # unknown host – show DNS / routing failure like real ping
        if ip not in self.env.network:
            print(f"ping: {ip}: Name or service not known")
            return

        host = self.env.network[ip]
        base_ms = host["latency"]  # CHANGED: per-host realistic latency
        name = host["name"]

        print(f"PING {ip} ({name}) 56(84) bytes of data.")

        # simulate N packets with jitter
        rtts = []
        for seq in range(count):
            jitter = random.uniform(-0.3, 0.8)  # realistic jitter
            ms = round(max(0.1, base_ms + jitter), 3)
            rtts.append(ms)
            print(f"64 bytes from {ip}: icmp_seq={seq} ttl=64 time={ms} ms")
            if seq < count - 1:
                time.sleep(0.05)  # tiny sleep makes it feel live

        # print real ping statistics block
        avg = round(sum(rtts) / len(rtts), 3)
        mdev = round(max(rtts) - min(rtts), 3)
        print(f"\n--- {ip} ping statistics ---")
        print(f"{count} packets transmitted, {count} received, 0% packet loss, time {count * 1000}ms")
        print(f"rtt min/avg/max/mdev = {min(rtts)}/{avg}/{max(rtts)}/{mdev} ms")

    def scan(self, args):
        prefix = args[0] if args else ""

        # nmap-style header
        # TODO: change print statement
        print(f"Starting scan of 192.168.0.0/24")
        print(f"Host discovery enabled. Scan report:\n")
        time.sleep(0.15)  # slight pause for realism

        found_hosts = {
            ip: info for ip, info in self.env.network.items()
            if not prefix or ip.startswith(prefix)
        }

        if not found_hosts:
            print("Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn")
            print("Nmap done: 0 IP addresses (0 hosts up) scanned")
            return

        # per-host block with port table
        for ip, info in sorted(found_hosts.items()):
            base_ms = info["latency"]
            jitter = random.uniform(-0.2, 0.5)
            latency = round(max(0.1, base_ms + jitter), 2)

            print(f"Nmap scan report for {info['name']} ({ip})")
            print(f"Host is up ({latency}ms latency).")

            # show services column using the new "services" dict
            services = info.get("services", {})
            if services:
                print(f"{'PORT':<10}  {'STATE':<8}  {'SERVICE'}")
                for port, svc in sorted(services.items()):
                    print(f"{str(port) + '/tcp':<10}  {'open':<8}  {svc}")

            # show OS if available
            if info.get("os"):
                print(f"OS: {info['os']}")

            # hint about auth requirement
            if not info.get("public", True):
                print(f"Note: Authentication required to connect.")
            else:
                print(f"Note: Open access – no authentication required.")

            print()  # blank line between hosts

        # nmap-style footer
        total = len(found_hosts)
        print(f"Nmap done: 254 IP addresses ({total} host{'s' if total != 1 else ''} up) scanned")

    def connect(self, args):
        if not args:
            print("usage: connect <ip>"); return

        ip = args[0]

        # unknown IP – realistic connection refused
        if ip not in self.env.network:
            print(f"ssh: connect to host {ip} port 22: Connection refused")
            return

        host = self.env.network[ip]
        name = host["name"]

        # always show SSH handshake negotiation header
        print(f"SSH client version: OpenSSH_9.6p1")
        print(f"Connecting to {ip} ({name}) port 22...")
        time.sleep(0.1)  # handshake delay
        print(f"Connection established.")
        print(f"Server SSH version: SSH-2.0-OpenSSH_8.9p1")
        time.sleep(0.05)

        # ---- Case 1: public host – no auth needed ----
        if host.get("public", True):
            print(f"Authenticated (publickey).\n")
            self._show_banner(ip, host)
            return

        # ---- Case 2+3: auth required ----
        # if already authenticated this session, skip prompt
        if ip in self.env.authenticated:
            print(f"Authenticated (cached session).\n")
            self._show_banner(ip, host)
            return

        auth_user = host.get("auth_user", "admin")
        correct_pw = host.get("password")  # None = honeypot

        print(f"Authentication required.")

        # allow up to 3 password attempts (mirrors real SSH)
        # TODO: change perhaps password amount
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                entered = input(f"{auth_user}@{ip}'s password: ")
            except EOFError:
                entered = ""

            # honeypot – always deny regardless of input
            if correct_pw is None:
                time.sleep(0.3)
                print(f"Permission denied, please try again.")
                if attempt == max_attempts:
                    print(f"{auth_user}@{ip}: Permission denied (publickey,password).")
                    print(f"ssh: connect to host {ip}: Too many authentication failures")
                continue

            # correct password → grant access
            if entered == correct_pw:
                time.sleep(0.1)
                print(f"Authenticated.\n")
                self.env.authenticated.add(ip)  # CHANGED: cache session
                self._show_banner(ip, host)
                return

            # wrong password – realistic SSH rejection message
            time.sleep(0.2)  # brief pause mimics server response time
            print(f"Permission denied, please try again.")

        # CHANGED: exhausted all attempts
        print(f"\n{auth_user}@{ip}: Permission denied (publickey,password).")
        print(f"ssh: connect to host {ip}: Too many authentication failures")

    def _show_banner(self, ip: str, host: dict):
        """Print the host banner, flag, and shell hint after successful login."""
        banner = host.get("banner", "")
        if banner:
            for line in banner.splitlines():
                print(f"  {line}")
            print()

        # flag is revealed only after successful authentication
        if "flag" in host:
            print(f"  ┌──────────────────────────────────────┐")
            print(f"  │         *** FLAG CAPTURED ***        │")
            print(f"  │  {host['flag']:<36}  │")
            print(f"  └──────────────────────────────────────┘")
            print()

        # show a context-aware hint to guide the player
        hint = host.get("shell_hint", "")
        if hint:
            print(f"  Hint: {hint}\n")

    def ifconfig(self, args):
        print("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500")
        print(f"        inet 192.168.0.5  netmask 255.255.255.0  broadcast 192.168.0.255")
        print(f"        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>")
        print(f"        ether 00:0c:29:ab:cd:ef  txqueuelen 1000  (Ethernet)")
        print(f"        RX packets 12345  bytes 8765432 (8.3 MiB)")
        print(f"        TX packets 9876   bytes 6543210 (6.2 MiB)")
        print()
        print("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536")
        print(f"        inet 127.0.0.1  netmask 255.0.0.0")
        print(f"        loop  txqueuelen 1000  (Local Loopback)")
        self.env.last_exit_code = 0

    def ip_cmd(self, args):
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

    def netstat(self, args):
        print(f"Active Internet connections (servers and established)")
        print(f"{'Proto':<6}  {'Local Address':<22}  {'Foreign Address':<22}  State")
        print(f"{'tcp':<6}  {'0.0.0.0:22':<22}  {'0.0.0.0:*':<22}  LISTEN")
        print(f"{'tcp':<6}  {'192.168.0.5:22':<22}  {'192.168.0.1:51234':<22}  ESTABLISHED")
        print(f"{'tcp':<6}  {'127.0.0.1:631':<22}  {'0.0.0.0:*':<22}  LISTEN")
        self.env.last_exit_code = 0

    def curl(self, args):
        flags = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            print("usage: curl [-s|-o <file>] <url>");
            return

        url = targets[0]
        # simulate responses for known hosts
        responses = {
            "http://192.168.0.10": (
                "<!DOCTYPE html>\n<html>\n<head><title>Cyber Lab Web Server</title></head>\n"
                "<body><h1>Welcome to the Cyber Lab</h1><p>Nothing to see here...</p></body>\n</html>"
            ),
            "http://192.168.0.10/": (
                "<!DOCTYPE html>\n<html>\n<head><title>Cyber Lab Web Server</title></head>\n"
                "<body><h1>Welcome to the Cyber Lab</h1><p>Nothing to see here...</p></body>\n</html>"
            ),
            "http://192.168.0.50:8080": (
                '{"status":"ok","message":"Admin panel running","version":"1.2.3"}'
            ),
        }

        content = responses.get(url, f"curl: (6) Could not resolve host: {url.split('/')[2] if '//' in url else url}")
        silent = "-s" in flags

        # check for -o output file
        if "-o" in flags:
            idx = flags.index("-o") if "-o" in flags else -1
            # find -o in original args
            for i, a in enumerate(args):
                if a == "-o" and i + 1 < len(args):
                    out_file = args[i + 1]
                    try:
                        node = self._get_or_create_file(out_file)
                        node.content = content
                        if not silent:
                            print(f"  % Total    % Received % Xferd")
                            print(
                                f"100   {len(content)}  100   {len(content)}    0     0  12345      0 --:--:-- --:--:-- --:--:-- 12345")
                    except Exception as e:
                        print(f"curl: {e}")
                    return

        print(content)
        self.env.last_exit_code = 0 if "curl: " not in content else 6

    def wget(self, args):
        if not args:
            print("usage: wget <url>");
            return
        url = args[0]
        filename = url.split("/")[-1] or "index.html"
        print(f"--2025-04-10 09:45:01--  {url}")
        print(f"Connecting to {url.split('/')[2] if '//' in url else url}... connected.")
        time.sleep(0.1)

        if "192.168.0.10" in url:
            content = "<html><body>Cyber Lab</body></html>"
            node = self._get_or_create_file(filename)
            node.content = content
            print(f"HTTP request sent, awaiting response... 200 OK")
            print(f"Length: {len(content)} [text/html]")
            print(f"Saving to: '{filename}'")
            print(f"'{filename}' saved [{len(content)}/{len(content)}]")
            self.env.last_exit_code = 0
        else:
            print(f"HTTP request sent, awaiting response... 404 Not Found")
            print(f"wget: server returned error: HTTP/1.1 404 Not Found")
            self.env.last_exit_code = 8

    def traceroute(self, args):
        if not args:
            print("usage: traceroute <ip>");
            return
        ip = args[0]
        print(f"traceroute to {ip}, 30 hops max, 60 byte packets")
        hops = [
            ("192.168.0.254", "gateway"),
            ("10.0.0.1", "isp-edge"),
        ]
        if ip in self.env.network:
            hops.append((ip, self.env.network[ip]["name"]))

        for i, (hop_ip, hop_name) in enumerate(hops, 1):
            base = random.uniform(1, 15)
            ms1, ms2, ms3 = round(base, 3), round(base + random.uniform(0, 1), 3), round(base + random.uniform(0, 2), 3)
            print(f" {i:2}  {hop_name} ({hop_ip})  {ms1} ms  {ms2} ms  {ms3} ms")
        self.env.last_exit_code = 0

    def nslookup(self, args):
        if not args:
            print("usage: nslookup <host>");
            return
        host = args[0]
        # check /etc/hosts
        hosts_node = self.env.root.children.get("etc", Node("etc", self.env.root)).children.get("hosts")
        if hosts_node:
            for line in hosts_node.content.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == host:
                    print(f"Server:\t\t127.0.0.53")
                    print(f"Address:\t127.0.0.53#53\n")
                    print(f"Non-authoritative answer:")
                    print(f"Name:\t{host}")
                    print(f"Address: {parts[0]}")
                    self.env.last_exit_code = 0
                    return
        print(f"Server:\t\t127.0.0.53")
        print(f"Address:\t127.0.0.53#53\n")
        print(f"** server can't find {host}: NXDOMAIN")
        self.env.last_exit_code = 1

    # =====================================================
    # SCRIPT ENGINE
    # =====================================================
    def run_script(self, args):
        if not args:
            print("usage: run <file.sh>"); return

        # support   run script.sh arg1 arg2
        script_path = args[0]
        script_args = args[1:]

        try:
            node = self.resolve_path(script_path)
        except FileNotFoundError as e:
            print(f"bash: {script_path}: No such file or directory, error: {e}")
            self.env.last_exit_code = 127
            return
        if node.is_dir:
            print(f"bash: {script_path}: Is a directory")
            self.env.last_exit_code = 126
            return

        # check execute permission
        if "x" not in node.permissions[:3]:
            print(f"bash: {script_path}: Permission denied")
            print(f"  (hint: chmod +x {script_path})")
            self.env.last_exit_code = 126
            return

        # positional args  $1 $2 …  $@  $#
        extra = {
            "0": script_path,
            "@": " ".join(script_args),
            "#": str(len(script_args)),
            "*": " ".join(script_args),
        }
        for i, a in enumerate(script_args, 1):
            extra[str(i)] = a

        lines = node.content.splitlines()
        # strip shebang
        if lines and lines[0].startswith("#!"):
            lines = lines[1:]

        interp = ScriptInterpreter(self)
        interp.run_lines(lines, extra_vars=extra)

    def source_cmd(self, args):
        """Source a script file in the current shell context."""
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
        interp = ScriptInterpreter(self)
        interp.run_lines(lines)

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
                "File System":   ["ls","cd","pwd","cat","nano","mkdir","touch","rm","cp","mv",
                                   "grep","find","head","tail","wc","sort","uniq","cut","diff",
                                   "chmod","chown","stat","du","df","file"],
                "Text/Shell":    ["echo","printf","export","unset","read","alias","type",
                                   "which","whoami","id","hostname","uname","uptime","date",
                                   "history","sleep","true","false","test","env","printenv","xargs"],
                "Process":       ["ps","kill","jobs"],
                "Network":       ["ping","scan","connect","ifconfig","ip","netstat","curl","wget","traceroute","nslookup"],
                "Scripting":     ["run","source","help","man","clear","exit"],
            }
            for group, names in groups.items():
                print(f"  {group}:")
                for n in names:
                    if n in self.commands:
                        cmd = self.commands[n]
                        print(f"    {cmd.usage:<40} {cmd.description}")
                print()

    def man_cmd(self, args):
        if not args:
            print("What manual page do you want?"); return
        cmd_name = args[0]
        if cmd_name in self.commands:
            cmd = self.commands[cmd_name]
            print(f"\nNAME")
            print(f"       {cmd_name} — {cmd.description}")
            print(f"\nSYNOPSIS")
            print(f"       {cmd.usage}")
            print(f"\nDESCRIPTION")
            print(f"       {cmd.description}.")
            print()
        else:
            print(f"No manual entry for {cmd_name}")
            self.env.last_exit_code = 1

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
            prompt = f"{env.user}@{env.hostname}:{path}$ "
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print("\nlogout")
            break

        if line.strip() == "exit":
            print("logout")
            break

        try:
            shell.run(line)
        except SystemExit as e:
            print(f"logout (exit code {e.code})")
            break


if __name__ == "__main__":
    main()