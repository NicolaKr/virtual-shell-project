# Script interpreter implementation extracted from virtual_shell.py

import shlex
import re
import io
import sys
from typing import Optional
from env import Node


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

        # Pre-pass: expand one-liner compound commands into multi-line form.
        # e.g. "for i in a b; do echo $i; done"
        #   -> ["for i in a b", "do", "echo $i", "done"]
        lines = self._expand_one_liners(lines)

        # first pass: collect function definitions
        lines = self._extract_functions(lines)

        idx = 0
        while idx < len(lines):
            line = lines[idx].strip()

            if not line or line.startswith("#"):
                idx += 1
                continue

            # Expand single-line compound commands joined by semicolons
            # e.g. "for i in 1 2 3; do echo $i; done"  →  keep as-is (handled below)
            # But bare semicolons outside a compound → split into multiple lines
            if ";" in line and not re.match(r"^(for|while|until|if)\b", line):
                sub_lines = [s.strip() for s in line.split(";") if s.strip()]
                if len(sub_lines) > 1:
                    # re-insert as separate lines and re-process
                    lines = lines[:idx] + sub_lines + lines[idx+1:]
                    continue

            # control structures
            if re.match(r"^if\b", line):
                idx = self._handle_if(lines, idx)
                continue
            if re.match(r"^for\b", line):
                idx = self._handle_for(lines, idx)
                continue
            if re.match(r"^while\b", line) or re.match(r"^until\b", line):
                idx = self._handle_while(lines, idx)
                continue

            # function return
            if line.startswith("return"):
                parts = line.split()
                val = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                self._return_value = val
                return val

            # normal line
            self._run_line(line)
            if self._return_value is not None:
                return self._return_value
            idx += 1

        return self._return_value or 0

    # ------------------------------------------------------------------
    # control structure parsers
    # ------------------------------------------------------------------
    def _expand_one_liners(self, lines: list[str]) -> list[str]:
        """Expand semicolon-separated one-liners into separate lines.

        "for i in a b; do echo $i; done"
          → ["for i in a b", "do", "  echo $i", "done"]

        Plain semicolons outside compound commands are also split:
          "cd /tmp; ls"  → ["cd /tmp", "ls"]
        """
        result = []
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                result.append(raw)
                continue

            is_compound = re.match(r'^(for|while|until|if)', line)

            if ";" not in line or not is_compound:
                # Not a compound one-liner – split on plain semicolons
                if ";" in line and not is_compound:
                    for part in line.split(";"):
                        p = part.strip()
                        if p:
                            result.append(p)
                else:
                    result.append(raw)
                continue

            # Compound one-liner: tokenise on ";" respecting nested ()
            tokens = self._split_on_semicolons(line)
            result.extend(tokens)

        return result

    def _split_on_semicolons(self, line: str) -> list:
        """Split a compound one-liner on semicolons, keeping keywords as
        their own tokens, and returning the whole thing as a list of lines."""
        parts = []
        depth = 0
        cur = ""
        for ch in line:
            if ch == "(":
                depth += 1
                cur += ch
            elif ch == ")":
                depth -= 1
                cur += ch
            elif ch == ";" and depth == 0:
                tok = cur.strip()
                if tok:
                    parts.append(tok)
                cur = ""
            else:
                cur += ch
        if cur.strip():
            parts.append(cur.strip())

        # Now reassemble: keywords "do"/"then" go on their own line;
        # body lines are kept as separate lines; "done"/"fi" close.
        expanded = []
        for part in parts:
            # "do cmd" → "do" + "  cmd" (if body mixed in)
            m_do = re.match(r'^do\s+(.+)$', part)
            if m_do:
                expanded.append("do")
                # body may itself contain semicolons
                for bp in m_do.group(1).split(";"):
                    bp = bp.strip()
                    if bp and bp != "done":
                        expanded.append("  " + bp)
                    elif bp == "done":
                        expanded.append("done")
                continue
            m_then = re.match(r'^then\s+(.+)$', part)
            if m_then:
                expanded.append("then")
                for bp in m_then.group(1).split(";"):
                    bp = bp.strip()
                    if bp and bp not in ("fi","else"):
                        expanded.append("  " + bp)
                    elif bp in ("fi","else"):
                        expanded.append(bp)
                continue
            expanded.append(part)

        return expanded

    def _extract_functions(self, lines: list[str]) -> list[str]:
        out = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = re.match(r"^([A-Za-z_]\w*)\s*\(\)\s*\{", line)
            if m:
                name = m.group(1)
                # collect until matching '}' on its own line
                body = []
                i += 1
                depth = 1
                while i < len(lines) and depth > 0:
                    l = lines[i]
                    if "{" in l:
                        depth += l.count("{")
                    if "}" in l:
                        depth -= l.count("}")
                        if depth == 0:
                            break
                    body.append(l)
                    i += 1
                self._functions[name] = body
                i += 1
                continue
            out.append(lines[i])
            i += 1
        return out

    def _handle_if(self, lines: list[str], idx: int) -> int:
        # find matching fi and split into branches
        end = idx + 1
        depth = 1
        while end < len(lines) and depth > 0:
            if re.match(r"^if\b", lines[end].strip()):
                depth += 1
            if re.match(r"^fi\b", lines[end].strip()):
                depth -= 1
                if depth == 0:
                    break
            end += 1

        block = lines[idx:end + 1]
        # split into if/elif/else parts
        parts = []
        cur = []
        header = None
        for l in block:
            s = l.strip()
            if re.match(r"^if\b", s) or re.match(r"^elif\b", s):
                if header is not None:
                    parts.append((header, cur))
                header = s
                cur = []
            elif s == "else":
                if header is not None:
                    parts.append((header, cur))
                header = "else"
                cur = []
            elif s == "fi":
                if header is not None:
                    parts.append((header, cur))
                header = None
            else:
                if header is not None:
                    cur.append(l)
        # evaluate
        executed = False
        for header, body in parts:
            if header == "else":
                if not executed:
                    self.run_lines([b for b in body])
                    executed = True
                continue
            # header like 'if test ...' or 'elif test ...'
            condition = header.split(None, 1)[1] if " " in header else ""
            si = ScriptInterpreter(self.shell)
            si._local_vars = dict(self._local_vars)
            res = si._eval_test(condition)
            if res and not executed:
                self.run_lines(body)
                executed = True
        return end + 1

    def _handle_for(self, lines: list[str], idx: int) -> int:
        # for VAR in ...; do ... done
        header = lines[idx].strip()
        # normalise:  "for i in list; do"  →  "for i in list"
        header_clean = re.sub(r";?\s*do\s*$", "", header).strip()
        m = re.match(r"^for\s+(\w+)\s+in\s+(.*)", header_clean)
        if not m:
            # malformed
            return idx + 1
        var = m.group(1)
        rest = m.group(2)
        # strip trailing ; do
        rest = re.sub(r";?\s*do\s*$", "", rest).strip()
        # expand brace sequences like {1..254}
        raw_items = rest.split()
        items = []
        for tok in raw_items:
            items.extend(self._expand_braces(self._expand(tok)))
        # find done
        end = idx + 1
        depth = 1
        while end < len(lines) and depth > 0:
            if lines[end].strip().startswith("for "):
                depth += 1
            if lines[end].strip() == "done":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        raw_body = lines[idx + 1:end]
        # Strip bare "do" delimiter lines and "do " prefix (from one-liner expansion)
        body = []
        for bl in raw_body:
            bs = bl.strip()
            if bs == "do":
                continue
            if bs.startswith("do "):
                body.append(bs[3:])
            else:
                body.append(bl)
        for it in items:
            self._local_vars[var] = it
            self.run_lines(body)
            if self._break_flag:
                self._break_flag = False
                break
            if self._continue_flag:
                self._continue_flag = False
                continue
        return end + 1

    def _handle_while(self, lines: list[str], idx: int) -> int:
        header = lines[idx].strip()
        cond = header.split(None, 1)[1] if " " in header else ""
        end = idx + 1
        depth = 1
        while end < len(lines) and depth > 0:
            if re.match(r"^while\b", lines[end].strip()) or re.match(r"^until\b", lines[end].strip()):
                depth += 1
            if lines[end].strip() == "done":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        raw_body_w = lines[idx + 1:end]
        body = []
        for bl in raw_body_w:
            bs = bl.strip()
            if bs == "do":
                continue
            if bs.startswith("do "):
                body.append(bs[3:])
            else:
                body.append(bl)
        # loop until condition false (while) or true (until)
        is_until = header.startswith("until")
        while True:
            si = ScriptInterpreter(self.shell)
            si._local_vars = dict(self._local_vars)
            res = si._eval_test(cond)
            if is_until:
                ok = not res
            else:
                ok = res
            if not ok:
                break
            self.run_lines(body)
            if self._break_flag:
                self._break_flag = False
                break
            if self._continue_flag:
                self._continue_flag = False
                continue
        return end + 1

    # ------------------------------------------------------------------
    # line execution and helpers
    # ------------------------------------------------------------------
    def _run_line(self, line: str):
        line = line.strip()

        # Strip background operator & — run synchronously in simulation
        # Handle:  cmd &    (cmd ...) &    cmd > /dev/null &
        line = re.sub(r'\s*&\s*$', '', line).strip()

        # Unwrap bare subshell grouping: ( cmd args )  →  cmd args
        # Must happen AFTER & strip so "(cmd) &" → "(cmd)" → "cmd"
        m_sub = re.match(r'^\(\s*(.+?)\s*\)\s*$', line)
        if m_sub:
            line = m_sub.group(1).strip()

        # Suppress /dev/null redirections silently
        line = re.sub(r'\s+>\s*/dev/null(\s+2>&1)?', '', line)
        line = re.sub(r'\s+2>/dev/null',              '', line)
        line = re.sub(r'\s+&>/dev/null',              '', line)

        # support 'break' and 'continue' inside loops
        if line.strip() == "break":
            self._break_flag = True
            return
        if line.strip() == "continue":
            self._continue_flag = True
            return
        # wait – no-op in synchronous simulation
        if re.match(r"^wait(\s|$)", line.strip()):
            return

        # variable assignment with local
        m = re.match(r"^local\s+(\w+)=(.*)", line)
        if m:
            k, v = m.group(1), self._expand(m.group(2))
            self._local_vars[k] = v
            self.env.vars[k] = v
            return

        m = re.match(r"^([A-Za-z_]\w*)=(.*)", line)
        if m and " " not in m.group(1):
            k, v = m.group(1), self._expand(m.group(2))
            self.env.vars[k] = v
            self._local_vars[k] = v
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


    def _expand_braces(self, text: str) -> list:
        """Expand {N..M} or {N...M} brace sequences like bash.
        Tolerates extra dots (common typo).  Returns list of words."""
        m = re.match(r'^(.*?)\{(\d+)\.{2,3}(\d+)\}(.*)$', text)
        if not m:
            return [text]
        pre, lo, hi, post = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
        step = 1 if hi >= lo else -1
        result = []
        for i in range(lo, hi + step, step):
            expanded = pre + str(i) + post
            # recurse for nested braces
            result.extend(self._expand_braces(expanded))
        return result

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