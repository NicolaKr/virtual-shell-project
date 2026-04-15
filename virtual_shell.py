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
            "ping": self.ping,
            "scan": self.scan,
            "connect": self.connect,
            "run": self.run_script,
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
        filename = args[0]

        try:
            with open(filename) as f:
                lines = f.readlines()
        except:
            print("file not found")
            return

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
    main()
