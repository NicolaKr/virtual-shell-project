"""helper.py – help content and rendering for the virtual shell.

Everything that used to live in Shell.HELP_DETAIL, Shell._load_command_help,
Shell.help(), and Shell.man_cmd() now lives here, keeping shell.py focused on
command execution.

Public API
----------
HELP_DETAIL  – dict of detailed help entries (merged from all command modules)
render_help  – renders 'help [command]' output; called by Shell.help()
render_man   – renders 'man <command>'  output; called by Shell.man_cmd()
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shell import Shell   # only used for type hints – avoids circular import


# ===========================================================================
# Help content
# ===========================================================================

# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------
_FS: dict = {
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
            ("cat file.txt",            "print file.txt"),
            ("cat /etc/passwd",         "print the system password file"),
            ("cat file1.txt file2.txt", "print two files one after the other"),
        ],
        "tip": "For long files use 'head', 'tail', or pipe through 'less'.",
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
    "nano": {
        "desc": "Open the interactive text editor.",
        "flags": [],
        "examples": [
            ("nano file.txt",         "open or create file.txt for editing"),
            ("nano scripts/sweep.sh", "edit a script"),
        ],
        "tip": (
            "Controls inside nano:\n"
            "  Arrow keys      – move cursor\n"
            "  Ctrl+S          – save\n"
            "  Ctrl+Q / Ctrl+X – quit\n"
            "  Ctrl+K          – cut current line\n"
            "  Ctrl+U          – paste cut line\n"
            "  Ctrl+G          – show help inside nano"
        ),
    },
    "run": {
        "desc": "Execute a shell script file. The file must have execute permission (chmod +x).\nYou can also run scripts with ./script.sh – the ./ means 'in this directory'.",
        "flags": [],
        "examples": [
            ("run myscript.sh", "run a script in the current directory"),
            ("./myscript.sh", "same thing using the direct path syntax"),
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
        "tip": "Scripts must have +x before you can execute them (e.g. ./script.sh).",
    },
    "diff": {
        "desc": "Compare two files line by line and show the differences.",
        "flags": [],
        "examples": [("diff file1.txt file2.txt", "show differences between two files")],
        "tip": "Lines starting with < are from file1, > are from file2.",
    },
}

# ---------------------------------------------------------------------------
# Text / shell utilities
# ---------------------------------------------------------------------------
_TEXT: dict = {
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
    "awk": {
        "desc": (
            "Pattern-action text processor. Reads input line by line;\n"
            "for each line it tests every rule and runs the matching action."
        ),
        "flags": [],
        "examples": [
            ("awk '/error/ { print $0 }' file.txt",
             "print every line containing 'error'"),
            (r"nmap 192.168 | awk '/Nmap scan report for/ { ip=$NF; gsub(/[()]/, \"\", ip) } /authentication: open/ { print ip }'",
             "extract open-auth IPs from nmap output"),
            ("cat data.txt | awk '{ print $1 }'",
             "print the first field of every line"),
        ],
        "tip": (
            "Key variables:\n"
            "  $0        – the whole line\n"
            "  $1 $2 …   – individual whitespace-separated fields\n"
            "  $NF       – the last field on the line\n"
            "Key functions:\n"
            "  gsub(/pat/, \"repl\", var)  – replace all matches of pat in var\n"
            "Pattern types:\n"
            "  /regex/        – run action when line matches regex\n"
            "  var1 && var2   – run action when both variables are truthy"
        ),
    },
    "export": {
        "desc": "Set or display environment variables available to all commands.",
        "flags": [],
        "examples": [
            ("export",                     "list all current environment variables"),
            ("export TARGET=192.168.0.25", "set TARGET variable"),
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
            ("alias",             "list all currently defined aliases"),
            ("alias ll='ls -la'", "create alias ll for ls -la"),
        ],
        "tip": "Aliases only last for this session.",
    },
    "source": {
        "desc": (
            "Run a script file in the current shell. "
            "Variables set inside the script remain available."
        ),
        "flags": [],
        "examples": [("source setup.sh", "run setup.sh and keep its variables")],
        "tip": "Unlike 'run', source shares the current shell's variables with the script.",
    },
}

# ---------------------------------------------------------------------------
# Scripting
# ---------------------------------------------------------------------------
_SCRIPTING: dict = {
    "run": {
        "desc": (
            "Execute a shell script file. The file must have execute permission (chmod +x).\n"
            "You can also run scripts with ./script.sh – the ./ means 'in this directory'."
        ),
        "flags": [],
        "examples": [
            ("run myscript.sh",         "run a script in the current directory"),
            ("./myscript.sh",           "same thing using the direct path syntax"),
            ("run script.sh arg1 arg2", "pass arguments accessible as $1 $2"),
        ],
        "tip": "Don't forget: chmod +x script.sh before running it!",
    },
    "man": {
        "desc": "Display the manual page for a command.",
        "flags": [],
        "examples": [
            ("man ls",   "manual for ls"),
            ("man grep", "manual for grep"),
        ],
        "tip": "You can also use 'help <command>' for a shorter quick reference.",
    },
}

# ---------------------------------------------------------------------------
# Process
# ---------------------------------------------------------------------------
_PROCESS: dict = {
    "ps": {
        "desc": "Show a list of running processes.",
        "flags": [("-aux", "show all processes from all users")],
        "examples": [
            ("ps",      "show processes"),
            ("ps -aux", "show all processes"),
        ],
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
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
_NETWORK: dict = {
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
}


# ---------------------------------------------------------------------------
# Load HELP dicts from the three network command modules (ping, scan, connect)
# ---------------------------------------------------------------------------
def _load_module_help() -> dict:
    merged: dict = {}
    for module_path, attr in [
        ("commands.ping",    "HELP"),
        ("commands.scan",    "HELP"),
        ("commands.connect", "HELP"),
    ]:
        try:
            mod = __import__(module_path, fromlist=[attr])
            merged.update(getattr(mod, attr, {}))
        except Exception:
            pass   # module absent or import error – skip silently
    return merged


# ---------------------------------------------------------------------------
# Build the public HELP_DETAIL dict
# ---------------------------------------------------------------------------
HELP_DETAIL: dict = {}
HELP_DETAIL.update(_FS)
HELP_DETAIL.update(_TEXT)
HELP_DETAIL.update(_SCRIPTING)
HELP_DETAIL.update(_PROCESS)
HELP_DETAIL.update(_NETWORK)
HELP_DETAIL.update(_load_module_help())


# ===========================================================================
# Rendering helpers  (used by Shell.help and Shell.man_cmd)
# ===========================================================================

def render_help(shell: "Shell", args: list | None) -> None:
    """Render 'help [command]' output.  Called by Shell.help()."""
    if args:
        cmd_name = args[0]
        if cmd_name in HELP_DETAIL:
            detail = HELP_DETAIL[cmd_name]
            usage  = shell.commands[cmd_name].usage if cmd_name in shell.commands else cmd_name
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
                tip_lines = detail["tip"].splitlines()
                print(f"  ║")
                for i, ln in enumerate(tip_lines):
                    print(f"  ║  {'TIP: ' if i == 0 else '      '}{ln}")
            print(f"  ╚{'═' * 50}\n")
        elif cmd_name in shell.commands:
            cmd = shell.commands[cmd_name]
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
                              "history", "sleep", "true", "false", "test", "env", "printenv",
                              "xargs", "awk"],
            "Process":      ["ps", "kill", "jobs"],
            "Network":      ["ping", "nmap", "ssh", "ifconfig", "ip", "netstat",
                              "curl", "wget", "traceroute", "nslookup"],
            "Scripting":    ["run", "source", "help", "man", "clear", "exit"],
        }
        for group, names in groups.items():
            print(f"  {group}:")
            for n in names:
                if n in shell.commands:
                    cmd    = shell.commands[n]
                    marker = "✦" if n in HELP_DETAIL else " "
                    print(f"    {marker} {cmd.usage:<38} {cmd.description}")
            print()
        print("  ✦ = detailed help available  (try: help grep)")


def render_man(shell: "Shell", args: list) -> None:
    """Render 'man <command>' output.  Called by Shell.man_cmd()."""
    if not args:
        print("What manual page do you want?")
        return
    cmd_name = args[0]
    if cmd_name not in shell.commands:
        print(f"No manual entry for {cmd_name}")
        shell.env.last_exit_code = 1
        return
    cmd = shell.commands[cmd_name]
    print(f"\nNAME\n       {cmd_name} — {cmd.description}")
    print(f"\nSYNOPSIS\n       {cmd.usage}")
    if cmd_name in HELP_DETAIL:
        d = HELP_DETAIL[cmd_name]
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