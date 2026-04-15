import shlex
import time


# =========================================================
# FILE SYSTEM NODE
# =========================================================
class Node:
    def __init__(self, name, parent=None, is_dir=True, content=None):
        self.name = name
        self.parent = parent
        self.is_dir = is_dir
        self.content = content
        self.children = {}


# =========================================================
# VIRTUAL ENVIRONMENT
# =========================================================
class VirtualEnvironment:
    def __init__(self):
        self.root = Node("/")
        self.cwd = self.root
        self.vars = {}

        # -------------------------
        # FILE SYSTEM
        # -------------------------
        home = Node("home", self.root)
        etc = Node("etc", self.root)

        self.root.children["home"] = home
        self.root.children["etc"] = etc

        home.children["student.txt"] = Node(
            "student.txt", home, False, "welcome to the cyber lab"
        )
        home.children["notes.txt"] = Node(
            "notes.txt", home, False, "hint: scan the network"
        )

        etc.children["hosts"] = Node(
            "hosts", etc, False, "127.0.0.1 localhost"
        )

        # -------------------------
        # NETWORK (CTF WORLD)
        # -------------------------
        self.network = {
            "192.168.0.1": {"name": "router", "ports": [22, 80]},
            "192.168.0.10": {"name": "web-server", "ports": [80]},
            "192.168.0.25": {
                "name": "db-server",
                "ports": [3306],
                "flag": "FLAG{database_breach}"
            }
        }


# =========================================================
# SHELL ENGINE
# =========================================================
class Shell:
    def __init__(self, env):
        self.env = env

    # =====================================================
    # MAIN DISPATCH
    # =====================================================
    def run(self, line):
        line = line.strip()
        if not line:
            return

        # variable assignment
        if "=" in line and not line.startswith("scan"):
            key, value = line.split("=", 1)
            self.env.vars[key.strip()] = value.strip()
            return

        # variable substitution
        for k, v in self.env.vars.items():
            line = line.replace(f"${k}", v)

        try:
            parts = shlex.split(line)
        except:
            print("parse error")
            return

        cmd = parts[0]
        args = parts[1:]

        commands = {
            "ls": self.ls,
            "cd": self.cd,
            "pwd": self.pwd,
            "cat": self.cat,
            "echo": self.echo,
            "mkdir": self.mkdir,
            "touch" self.touch,
            "ping": self.ping,
            "scan": self.scan,
            "connect": self.connect,
            "run": self.run_script,
            "nano": self.nano,
            "help": self.help
        }

        if cmd in commands:
            commands[cmd](args)
        else:
            print("bash: command not found:", cmd)

    # =====================================================
    # PATH SYSTEM (REALISTIC)
    # =====================================================
    def resolve_path(self, path):
        if path == "":
            return self.env.cwd

        # absolute path
        if path.startswith("/"):
            node = self.env.root
            parts = path.split("/")[1:]
        else:
            node = self.env.cwd
            parts = path.split("/")

        for p in parts:
            if p in ("", "."):
                continue

            if p == "..":
                if node.parent:
                    node = node.parent
                continue

            if p not in node.children:
                raise Exception(f"no such file or directory: {path}")

            node = node.children[p]

        return node

    def get_path(self, node):
        parts = []
        while node.parent is not None:
            parts.append(node.name)
            node = node.parent
        return "/" + "/".join(reversed(parts))

    def mkdir(self, args):
        if not args:
            print("mkdir: missing operand")
            return
        try:
            parent_node = self.env.cwd
            name = args[0]
            if "/" in name:
                parts = name.rsplit("/", 1)
                parent_node = self.resolve_path(parts[0])
                name = parts[1]
            if name in parent_node.children:
                print(f"mkdir: cannot create directory '{args[0]}': File exists")
                return
            parent_node.children[name] = Node(name, parent_node, is_dir=True)
        except Exception as e:
            print(e)

    def touch(self, args):
        if not args:
            print("touch: missing operand")
            return
        try:
            parent_node = self.env.cwd
            name = args[0]
            if "/" in name:
                parts = name.rsplit("/", 1)
                parent_node = self.resolve_path(parts[0])
                name = parts[1]
            if name not in parent_node.children:
                parent_node.children[name] = Node(name, parent_node, is_dir=False, content="")
        except Exception as e:
            print(e)


    # =====================================================
    # FILE COMMANDS
    # =====================================================
    def ls(self, args):
        node = self.env.cwd
        print("  ".join(node.children.keys()))

    def cd(self, args):
        if not args:
            return
        try:
            node = self.resolve_path(args[0])
            if not node.is_dir:
                print("not a directory")
                return
            self.env.cwd = node
        except Exception as e:
            print(e)

    def pwd(self, args):
        print(self.get_path(self.env.cwd))

    def cat(self, args):
        if not args:
            return
        node = self.resolve_path(args[0])
        if node.is_dir:
            print("is a directory")
        else:
            print(node.content)

    def nano(self, args):
        if not args:
            print("usage: nano <filename>")
            return

        filename = args[0]

        # Resolve parent directory and filename
        parts = filename.rsplit("/", 1)
        if len(parts) == 2:
            try:
                parent = self.resolve_path(parts[0])
            except Exception as e:
                print(e)
                return
            name = parts[1]
        else:
            parent = self.env.cwd
            name = parts[0]

        # Load existing content if file exists
        existing_content = ""
        if name in parent.children and not parent.children[name].is_dir:
            existing_content = parent.children[name].content or ""
            if existing_content:
                print("Editing existing file. Current content:")
                for i, line in enumerate(existing_content.splitlines(), 1):
                    print(f"  {i:3}: {line}")
                print()

        # Determine syntax hint
        ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
        hints = {
            "py": "Python", "sh": "Shell script", "txt": "Text",
            "md": "Markdown", "json": "JSON", "js": "JavaScript",
            "html": "HTML", "css": "CSS", "rb": "Ruby", "c": "C",
            "cpp": "C++", "rs": "Rust", "go": "Go", "yaml": "YAML",
        }
        hint = hints.get(ext, "File")

        print(f"  nano — {hint}: {filename}")
        print("  Enter lines below. Type ':wq' to save, ':q!' to cancel.\n")

        lines = []
        while True:
            try:
                line = input("  > ")
            except EOFError:
                break

            if line.strip() == ":wq":
                break
            if line.strip() == ":q!":
                print("cancelled — no changes saved")
                return

            lines.append(line)

        content = "\n".join(lines)
        parent.children[name] = Node(name, parent, is_dir=False, content=content)
        print(f'\n  saved "{filename}" ({len(lines)} lines)')

    def echo(self, args):
        print(" ".join(args))

    def rm(self, args):
        if not args:
            print("rm: missing operand")
            return
        try:
            node = self.resolve_path(args[0])
            if node.is_dir and "-r" not in args:
                print(f"rm: cannot remove '{args[0]}': Is a directory (use -r)")
                return
            node.parent.children.pop(node.name)
        except Exception as e:
            print(e)

    def cp(self, args):
        if len(args) < 2:
            print("cp: missing operand")
            return
        try:
            src = self.resolve_path(args[0])
            if src.is_dir:
                print("cp: -r not supported for directories")
                return
            dest_parent = self.env.cwd
            dest_name = args[1]
            if "/" in args[1]:
                parts = args[1].rsplit("/", 1)
                dest_parent = self.resolve_path(parts[0])
                dest_name = parts[1]
            elif args[1] in dest_parent.children and dest_parent.children[args[1]].is_dir:
                dest_parent = dest_parent.children[args[1]]
                dest_name = src.name
            dest_parent.children[dest_name] = Node(dest_name, dest_parent, is_dir=False, content=src.content)
        except Exception as e:
            print(e)

    def mv(self, args):
        if len(args) < 2:
            print("mv: missing operand")
            return
        try:
            src = self.resolve_path(args[0])
            dest_parent = self.env.cwd
            dest_name = args[1]
            if "/" in args[1]:
                parts = args[1].rsplit("/", 1)
                dest_parent = self.resolve_path(parts[0])
                dest_name = parts[1]
            elif args[1] in dest_parent.children and dest_parent.children[args[1]].is_dir:
                dest_parent = dest_parent.children[args[1]]
                dest_name = src.name
            src.parent.children.pop(src.name)
            src.name = dest_name
            src.parent = dest_parent
            dest_parent.children[dest_name] = src
        except Exception as e:
            print(e)

    def grep(self, args):
        if len(args) < 2:
            print("usage: grep <pattern> <file>")
            return
        pattern = args[0]
        try:
            node = self.resolve_path(args[1])
            if node.is_dir:
                print("grep: is a directory")
                return
            for line in node.content.splitlines():
                if pattern in line:
                    print(line)
        except Exception as e:
            print(e)

    def export(self, args):
        if not args:
            for k, v in self.env.vars.items():
                print(f"{k}={v}")
            return
        for arg in args:
            if "=" in arg:
                k, v = arg.split("=", 1)
                self.env.vars[k.strip()] = v.strip()

    # =====================================================
    # NETWORK COMMANDS
    # =====================================================
    def ping(self, args):
        ip = args[0]
        if ip in self.env.network:
            print(f"{ip} is alive")
        else:
            print(f"{ip} unreachable")

    def scan(self, args):
        print("[*] scanning network...\n")
        time.sleep(0.2)

        prefix = args[0] if args else ""  # optional argument

        found = False
        for ip, info in self.env.network.items():
            if prefix == "" or ip.startswith(prefix):
                found = True
                print(f"{ip} ({info['name']})")

        if not found:
            print("no hosts found")


    def connect(self, args):
        ip = args[0]

        if ip not in self.env.network:
            print("connection failed")
            return

        host = self.env.network[ip]
        print(f"connected to {ip} ({host['name']})")
        print("open ports:", host["ports"])

        if "flag" in host:
            print("\n🎯 FLAG:", host["flag"])

    # =====================================================
    # SCRIPT ENGINE
    # =====================================================
    def run_script(self, args):

        if not args:
            print("usage: run <file.sh>")
            return


        filename = args[0]

        try:
            node = self.resolve_path(filename)
        except Exception as e:
            print("Can't run script, Error:", e)
            return

        if node.is_dir:
            print("run: is a directory, can't execute")
            return

        lines = node.content.splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for k, v in self.env.vars.items():
                line = line.replace(f"${k}", v)

            print(f"$ {line}")
            self.run(line)

    # =====================================================
    # HELP
    # =====================================================
    def help(self, args=None):
        print("""
Commands:
  ls
  cd <path>
  pwd
  cat <file>
  nano <file> 
  ping <ip>
  scan <prefix>
  connect <ip>
  run <file.sh>
  var=value
  exit
""")


# =========================================================
# JUPYTER TERMINAL LOOP
# =========================================================
def main():
    from virtual_shell import VirtualEnvironment, Shell

    env = VirtualEnvironment()
    shell = Shell(env)

    print("Cyber Shell Lab (type 'help')")

    while True:
        path = shell.get_path(env.cwd)
        cmd = input(f"cyber-shell:{path}$ ")

        if cmd.strip() == "exit":
            break

        shell.run(cmd)


if __name__ == "__main__":
    print("Finished Environment Exists")
    main()
