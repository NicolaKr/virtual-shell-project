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
      - Brace groups  { … } [> file]
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

        # Pre-pass: join lines where a single quote is opened but not closed.
        # This handles multiline awk '...' blocks written across several lines.
        joined: list[str] = []
        pending = ""
        for raw in lines:
            if pending:
                pending += " " + raw
            else:
                pending = raw
            # count unescaped single quotes
            if pending.count("'") % 2 == 0:
                joined.append(pending)
                pending = ""
        if pending:
            joined.append(pending)  # unclosed quote at EOF – try anyway
        lines = joined

        # Pre-pass: join pipe-continuation lines (lines ending with a bare |).
        # e.g.   nmap 192.168 |
        #        awk '...' |
        #        sort -u
        # becomes a single line: nmap 192.168 | awk '...' | sort -u
        pipe_joined: list[str] = []
        pipe_pending = ""
        for raw in lines:
            stripped = raw.strip()
            if pipe_pending:
                pipe_pending = pipe_pending.rstrip() + " " + stripped
            else:
                pipe_pending = stripped
            # A line ending with | (not ||) means continuation
            if re.search(r'(?<!\|)\|(?!\|)\s*$', pipe_pending):
                continue   # keep accumulating
            pipe_joined.append(pipe_pending)
            pipe_pending = ""
        if pipe_pending:
            pipe_joined.append(pipe_pending)
        lines = pipe_joined

        # Pre-pass A: join a bare "then" or "do" onto the preceding keyword line.
        # Handles two cases:
        #   1. User wrote:   if [[ ... ]];        2. User wrote:  if [[ ... ]]; then
        #                    then                  (after ; split → bare "then" token)
        # Both produce a standalone "then" that must be folded back.
        _then_joined: list[str] = []
        _ti = 0
        while _ti < len(lines):
            _cur = lines[_ti]
            _nxt = lines[_ti + 1].strip() if _ti + 1 < len(lines) else ""
            if (_nxt in ("then", "do") and
                    re.match(r"^(if|elif|while|until|for)", _cur.strip())):
                # strip trailing semicolons before appending "; then/do"
                _cur = _cur.rstrip().rstrip(";").rstrip() + "; " + _nxt
                _ti += 2
            else:
                _ti += 1
            _then_joined.append(_cur)
        lines = _then_joined

        # Pre-pass B: expand one-liner compound commands into multi-line form.
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
            # Quote-aware: don't split on ; inside single or double quotes
            if ";" in line and not re.match(r"^(for|while|until|if)\b", line):
                def _qsemi_split(s):
                    parts, buf, in_q, depth = [], [], None, 0
                    for ch in s:
                        if in_q:
                            buf.append(ch)
                            if ch == in_q: in_q = None
                        elif ch in ('"', "'"):
                            in_q = ch; buf.append(ch)
                        elif ch == "{":
                            depth += 1; buf.append(ch)
                        elif ch == "}":
                            depth -= 1; buf.append(ch)
                        elif ch == ";" and depth == 0:
                            parts.append("".join(buf).strip())
                            buf = []
                        else:
                            buf.append(ch)
                    parts.append("".join(buf).strip())
                    return [p for p in parts if p]
                sub_lines = _qsemi_split(line)
                if len(sub_lines) > 1:
                    # re-insert as separate lines and re-process
                    lines = lines[:idx] + sub_lines + lines[idx+1:]
                    continue

            # Brace group:  { … }  or  { … } > file  or  { … } >> file
            # Handles the case where { is on its own line (multi-line brace group).
            if line == "{":
                body_lines = []
                idx += 1
                depth = 1
                while idx < len(lines) and depth > 0:
                    l = lines[idx].strip()
                    if l == "{":
                        depth += 1
                        body_lines.append(l)
                    elif l.startswith("}"):
                        depth -= 1
                        if depth == 0:
                            # check for redirect:  } > file  or  } >> file
                            m_redir = re.match(r'^\}\s*(>>?)\s+(\S+)', l)
                            if m_redir:
                                op, dest = m_redir.group(1), m_redir.group(2)
                                buf = io.StringIO()
                                old = sys.stdout
                                sys.stdout = buf
                                try:
                                    self.run_lines(list(body_lines))
                                finally:
                                    sys.stdout = old
                                result = buf.getvalue()
                                try:
                                    node = self.shell._get_or_create_file(dest)
                                    if ">>" in op:
                                        node.content += result
                                    else:
                                        node.content = result
                                    node.touch_mtime()
                                except Exception as e:
                                    print(f"bash: {e}")
                            else:
                                self.run_lines(list(body_lines))
                        else:
                            body_lines.append(l)
                    else:
                        body_lines.append(l)
                    idx += 1
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
            # ssh from a script — connect interactively, then continue locally
            if re.match(r'^ssh', line):
                import shlex as _shlex
                expanded = self._expand(line)
                try:
                    parts = _shlex.split(expanded)
                except Exception:
                    parts = expanded.split()
                remaining = [l.strip() for l in lines[idx+1:] if l.strip()]
                print("remaining:", remaining)
                from commands.connect import run_connect
                run_connect(self.shell, parts[1:], commands=remaining)
                return self._return_value or 0
            else:
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

            is_compound = re.match(r'^(for|while|until|if)', line)

            if ";" not in line or not is_compound:
                # Not a compound one-liner – split on plain semicolons (quote-aware)
                if ";" in line and not is_compound:
                    def _qsemi(s):
                        parts, buf, in_q, depth = [], [], None, 0
                        for ch in s:
                            if in_q:
                                buf.append(ch)
                                if ch == in_q: in_q = None
                            elif ch in ('"', "'"):
                                in_q = ch; buf.append(ch)
                            elif ch == "{":
                                depth += 1; buf.append(ch)
                            elif ch == "}":
                                depth -= 1; buf.append(ch)
                            elif ch == ";" and depth == 0:
                                p = "".join(buf).strip()
                                if p: parts.append(p)
                                buf = []
                            else:
                                buf.append(ch)
                        p = "".join(buf).strip()
                        if p: parts.append(p)
                        return parts
                    for part in _qsemi(line):
                        result.append(part)
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
            # bare "then" → fold onto preceding if/elif line
            if part.strip() == "then":
                if expanded and re.match(r'^(if|elif)', expanded[-1].strip()):
                    expanded[-1] = expanded[-1].rstrip().rstrip(";").rstrip() + "; then"
                continue

            # bare "do" → fold onto preceding while/for/until line
            if part.strip() == "do":
                if expanded and re.match(r'^(while|until|for)', expanded[-1].strip()):
                    expanded[-1] = expanded[-1].rstrip().rstrip(";").rstrip() + "; do"
                continue

            # "do cmd" → keep "do" inline, add body lines
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

            # "then cmd" → fold then onto preceding if/elif, add body lines
            m_then = re.match(r'^then\s+(.+)$', part)
            if m_then:
                if expanded and re.match(r'^(if|elif)', expanded[-1].strip()):
                    expanded[-1] = expanded[-1].rstrip().rstrip(";").rstrip() + "; then"
                else:
                    expanded.append("then")
                for bp in m_then.group(1).split(";"):
                    bp = bp.strip()
                    if bp and bp not in ("fi", "else"):
                        expanded.append("  " + bp)
                    elif bp in ("fi", "else"):
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
            condition = re.sub(r'\s*;?\s*then\s*$', '', condition).strip()
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
        # Expand command substitutions BEFORE word-splitting so that
        # "$(cat file)" isn't split into "$(cat" and "file)".
        rest_expanded = self._expand(rest)
        raw_items = rest_expanded.split()
        items = []
        for tok in raw_items:
            items.extend(self._expand_braces(tok))
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

        is_until = header.startswith("until")

        # extract condition part after "while"/"until"
        cond = header.split(None, 1)[1] if " " in header else ""

        # ------------------------------------------------------------
        # 1. SPECIAL CASE: while read VAR [< file]
        # ------------------------------------------------------------
        import re

        m = re.search(
            r'^(?:IFS=\S*\s+)?read(?:\s+-r)?\s+(\w+)(?:\s*<\s*(\S+))?$',
            cond.strip()
        )

        redirect_file = None
        read_var = None

        if m:
            read_var = m.group(1)
            redirect_file = m.group(2)

            # also allow:  while IFS= read -r var < file   (header-level redirect)
            if redirect_file is None:
                redir = re.search(r'<\s*(\S+)', header)
                if redir:
                    redirect_file = redir.group(1)

        # ------------------------------------------------------------
        # 2. parse body
        # ------------------------------------------------------------
        body = []
        i = idx + 1
        # Separate counters: while/for/until are closed by 'done',
        # if/case are closed by 'fi'/'esac' — they must not interfere.
        done_depth = 0
        fi_depth   = 0

        done_line = ""
        while i < len(lines):
            line = lines[i].strip()

            if re.match(r"^(while|until|for)\b", line):   done_depth += 1
            elif re.match(r"^if\b", line):                 fi_depth   += 1
            elif re.match(r"^case\b", line):               fi_depth   += 1
            elif re.match(r'^done\b', line):
                if done_depth == 0:
                    done_line = line
                    break
                done_depth -= 1
            elif re.match(r'^fi\b', line):                 fi_depth   -= 1
            elif re.match(r'^esac\b', line):               fi_depth   -= 1

            # skip bare 'do' delimiter (same as _handle_for)
            if line == "do":
                pass
            elif line.startswith("do "):
                body.append(line[3:])
            else:
                body.append(line)
            i += 1

        end = i

        # Pick up "< file" from "done < file" if not on the header line
        if m and redirect_file is None:
            redir = re.search(r'<\s*(\S+)', done_line)
            if redir:
                redirect_file = redir.group(1)

        # ------------------------------------------------------------
        # 3. HANDLE read-loop mode (NEW BEHAVIOR)
        # ------------------------------------------------------------
        if read_var and redirect_file:
            try:
                node = self.shell._get_or_create_file(redirect_file)
                file_lines = node.content.splitlines()
            except Exception:
                file_lines = []

            for line in file_lines:
                # assign variable (bash-style)
                self._local_vars[read_var] = line
                self.env.vars[read_var] = line

                self.run_lines(body)

                if self._break_flag:
                    self._break_flag = False
                    break

                if self._continue_flag:
                    self._continue_flag = False
                    continue

            return end + 1

        # ------------------------------------------------------------
        # 4. FALLBACK: normal while/until evaluation
        # ------------------------------------------------------------
        while True:
            si = ScriptInterpreter(self.shell)

            condition_result = si.run_lines([cond])

            cond_true = bool(condition_result)
            if is_until:
                cond_true = not cond_true

            if not cond_true:
                break

            si.run_lines(body)

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

        # && / || short-circuit operators
        # Handle:  [[ expr ]] && cmd   or   cmd1 && cmd2   or   cmd1 || cmd2
        # Must be done before variable assignment check.
        # Split only on top-level && / || (not inside quotes or [[ ]]).
        def _split_logic(s):
            parts = []
            buf = ""
            in_q = None
            i = 0
            while i < len(s):
                c = s[i]
                if in_q:
                    buf += c
                    if c == in_q:
                        in_q = None
                elif c in ('"', "'"):
                    in_q = c
                    buf += c
                elif s[i:i+2] in ("&&", "||"):
                    parts.append((buf.strip(), s[i:i+2]))
                    buf = ""
                    i += 2
                    continue
                else:
                    buf += c
                i += 1
            if buf.strip():
                parts.append((buf.strip(), None))
            return parts

        if "&&" in line or "||" in line:
            logic_parts = _split_logic(line)
            if len(logic_parts) > 1:
                for part_cmd, op in logic_parts:
                    if not part_cmd:
                        continue
                    # [[ expr ]] — evaluate as test, set exit code
                    m_dbl = re.match(r'^\[\[\s*(.*?)\s*\]\]$', part_cmd)
                    if m_dbl:
                        result = self._eval_test(part_cmd)
                        self.env.last_exit_code = 0 if result else 1
                    else:
                        self._run_line(part_cmd)
                    if op == "&&" and self.env.last_exit_code != 0:
                        break
                    if op == "||" and self.env.last_exit_code == 0:
                        break
                return

        # [[ expr ]] standalone
        m_dbl = re.match(r'^\[\[\s*(.*?)\s*\]\]$', line)
        if m_dbl:
            result = self._eval_test(line)
            self.env.last_exit_code = 0 if result else 1
            return

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

        # delegate to shell — expand variables first so $i, $ip etc. are resolved
        self.shell.run(self._expand(line))

    def _capture_line(self, line: str) -> str:
        """Run a line, capture stdout, return as string."""
        line = self._expand(line).strip()
        # Strip 2>/dev/null and similar redirections that shouldn't affect capture
        line = re.sub(r"\s+2>/dev/null", "", line)
        line = re.sub(r"\s+&>/dev/null", "", line)

        # ssh inside $(...) with a trailing command: ssh [flags] <ip> "cmd"
        # Pass the trailing command non-interactively and capture its output.
        m_ssh = re.match(r'^ssh\b(.*?)\s+([\'"])(.*?)\2\s*$', line, re.DOTALL)
        if not m_ssh:
            # also handle unquoted trailing command: ssh [flags] <ip> cmd
            m_ssh = re.match(r"^ssh\b(.+)$", line)
        if m_ssh:
            import shlex as _shlex
            try:
                parts = _shlex.split(line)
            except Exception:
                parts = line.split()
            if parts and parts[0] == "ssh":
                # Split: flags+ip vs trailing remote command
                # Find the ip (first non-flag arg), everything after is the command
                ssh_args = parts[1:]
                ip_idx = None
                i = 0
                while i < len(ssh_args):
                    if ssh_args[i] in ("-p", "-l") and i + 1 < len(ssh_args):
                        i += 2
                    elif ssh_args[i].startswith("-"):
                        i += 1
                    else:
                        ip_idx = i
                        break
                if ip_idx is not None and ip_idx + 1 < len(ssh_args):
                    # There IS a trailing command argument
                    connect_args = ssh_args[:ip_idx + 1]  # flags + ip
                    remote_cmd   = " ".join(ssh_args[ip_idx + 1:])
                    from commands.connect import run_connect
                    buf = io.StringIO()
                    old_out = sys.stdout
                    sys.stdout = buf
                    try:
                        run_connect(self.shell, connect_args, commands=[remote_cmd])
                    finally:
                        sys.stdout = old_out
                    # Strip SSH handshake noise from the captured output,
                    # keeping only lines that look like actual command output.
                    raw = buf.getvalue()
                    filtered = []
                    for ln in raw.splitlines():
                        if (ln.startswith("debug1:") or ln.startswith("SSH client") or
                                ln.startswith("Warning:") or ln.startswith("---") or
                                ln.startswith("The authenticity") or ln.startswith("ECDSA") or
                                ln.startswith("Are you sure") or not ln.strip()):
                            continue
                        filtered.append(ln)
                    return "\n".join(filtered) + ("\n" if filtered else "")

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

        # command substitution  $( cmd )  — depth-aware to handle nested parens
        def _cmd_subst(s):
            result = []
            i = 0
            while i < len(s):
                if s[i] == "$" and i + 1 < len(s) and s[i+1] == "(":
                    # check it's not $(( arithmetic ))
                    if i + 2 < len(s) and s[i+2] == "(":
                        result.append(s[i]); i += 1; continue
                    depth = 0; j = i + 1
                    while j < len(s):
                        if s[j] == "(": depth += 1
                        elif s[j] == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        j += 1
                    inner = s[i+2:j]
                    result.append(self._capture_line(inner).strip())
                    i = j + 1
                else:
                    result.append(s[i]); i += 1
            return "".join(result)
        text = _cmd_subst(text)

        # ${VAR:-default}
        text = re.sub(
            r"\$\{(\w+):-([^}]*)\}",
            lambda m: self.env.vars.get(m.group(1)) or self._local_vars.get(m.group(1)) or m.group(2),
            text
        )

        # ${VAR%pattern}  -- strip shortest suffix
        def _strip_suffix(m):
            val = self._local_vars.get(m.group(1), self.env.vars.get(m.group(1), ""))
            pat = m.group(2).strip('\"\' ')
            if pat and val.endswith(pat):
                return val[:-len(pat)]
            return val
        text = re.sub(r"\$\{(\w+)%([^}]*)\}", _strip_suffix, text)

        # ${VAR#pattern}  -- strip shortest prefix
        def _strip_prefix(m):
            val = self._local_vars.get(m.group(1), self.env.vars.get(m.group(1), ""))
            pat = m.group(2).strip('\"\' ')
            if pat and val.startswith(pat):
                return val[len(pat):]
            return val
        text = re.sub(r"\$\{(\w+)#([^}]*)\}", _strip_prefix, text)

        # ${VAR}
        text = re.sub(
            r"\$\{(\w+)\}",
            lambda m: str(self._local_vars.get(m.group(1), self.env.vars.get(m.group(1), ""))),
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

        # Strip surrounding quotes only for single-word values, not multi-token
        # expressions like '"foo" != "bar baz"' which _eval_test handles itself.
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
            inner = text[1:-1]
            if not any(c in inner for c in (" ", "\t")):
                text = inner

        return text

    # ------------------------------------------------------------------
    # _eval_test  –  evaluate [ … ] / [[ … ]] / test expressions
    # ------------------------------------------------------------------

    def _eval_test(self, expr: str) -> bool:
        """Evaluate a shell test expression. Returns True/False."""
        expr = expr.strip()

        # Strip outer [ ] or [[ ]]
        if expr.startswith("[[") and expr.endswith("]]"):
            expr = expr[2:-2].strip()
        elif expr.startswith("[") and expr.endswith("]"):
            expr = expr[1:-1].strip()
        elif expr.startswith("test "):
            expr = expr[5:].strip()

        expr = self._expand(expr)

        # Compound: && and ||
        # Simple left-to-right (no precedence)
        if " && " in expr:
            parts = expr.split(" && ", 1)
            return self._eval_test(parts[0]) and self._eval_test(parts[1])
        if " || " in expr:
            parts = expr.split(" || ", 1)
            return self._eval_test(parts[0]) or self._eval_test(parts[1])

        # Negation
        if expr.startswith("! "):
            return not self._eval_test(expr[2:])

        def _qtok(s):
            """Quote-aware tokeniser: "hello world" → one token, empty "" → empty token."""
            tokens, buf, in_q, was_quoted = [], [], None, False
            for ch in s:
                if in_q:
                    if ch == in_q: in_q = None
                    else: buf.append(ch)
                elif ch in ('"', "'"):
                    in_q = ch; was_quoted = True
                elif ch in (" ", "\t"):
                    if buf or was_quoted:
                        tokens.append("".join(buf)); buf = []; was_quoted = False
                else:
                    buf.append(ch)
            if buf or was_quoted:
                tokens.append("".join(buf))
            return tokens
        tokens = _qtok(expr)

        # Unary file tests
        if len(tokens) == 2 and tokens[0] in ("-f", "-d", "-e", "-r", "-w", "-x", "-s", "-z", "-n"):
            flag, val = tokens[0], tokens[1]
            if flag == "-z": return len(val) == 0
            if flag == "-n": return len(val) > 0
            # For the virtual FS, treat any non-empty string as "exists"
            if flag in ("-e", "-f", "-d", "-r", "-w", "-x", "-s"):
                try:
                    node = self.shell.resolve_path(val)
                    if flag == "-d": return node.is_dir
                    if flag == "-f": return not node.is_dir
                    if flag == "-s": return node.size > 0
                    return True
                except Exception:
                    return False

        # Binary comparisons
        if len(tokens) >= 3:
            lhs, op, rhs = tokens[0], tokens[1], " ".join(tokens[2:])
            if op == "==" or op == "=":  return lhs == rhs
            if op == "!=":               return lhs != rhs
            if op == "-eq":
                try: return int(lhs) == int(rhs)
                except ValueError: return False
            if op == "-ne":
                try: return int(lhs) != int(rhs)
                except ValueError: return False
            if op == "-lt":
                try: return int(lhs) < int(rhs)
                except ValueError: return False
            if op == "-le":
                try: return int(lhs) <= int(rhs)
                except ValueError: return False
            if op == "-gt":
                try: return int(lhs) > int(rhs)
                except ValueError: return False
            if op == "-ge":
                try: return int(lhs) >= int(rhs)
                except ValueError: return False

        # Plain string / command truthiness
        if not tokens:
            return False
        # single token: truthy if non-empty and not "0" or "false"
        if len(tokens) == 1:
            return bool(tokens[0]) and tokens[0] not in ("0", "false", "")

        return False