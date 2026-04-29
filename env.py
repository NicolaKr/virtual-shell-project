import datetime
import random
import string
from typing import Dict, Any

# Minimal filesystem node used by the virtual environment
class Node:
    def __init__(self, name, parent=None, is_dir=True, content=None, permissions=None, owner="student"):
        self.name = name
        self.parent = parent
        self.is_dir = is_dir
        self.content = content or ""
        self.owner = owner
        self.permissions = permissions or ("rwxr-xr-x" if is_dir else "rw-r--r--")

        self.children = {}
        self.mtime = datetime.datetime.now()

    @property
    def size(self):
        if self.is_dir:
            return 4096
        return len(self.content.encode())

    @property
    def mtime_str(self):
        now = datetime.datetime.now()
        if self.mtime.year == now.year:
            return self.mtime.strftime("%b %d %H:%M")
        return self.mtime.strftime("%b %d  %Y")

    def touch_mtime(self) -> None:
        self.mtime = datetime.datetime.now()

    def permission_bits(self):
        p = self.permissions
        result = 0
        mapping = {"r": 4, "w": 2, "x": 1}
        for i, ch in enumerate(p):
            if ch != "-":
                result |= mapping[ch] << (6 - (i // 3) * 3)
        return result


class VirtualEnvironment:
    def __init__(self, codename: str = "", num_public: int = 5, num_private: int = 3):
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
        self.last_exit_code = 0

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

        # populate network by parameters
        self.generate_random_network(codename, num_public, num_private)

        self.authenticated = set()

    def generate_random_network(self, codename: str, num_public: int = 5, num_private: int = 3) -> None:
        # internal helper implementation
        if num_public <= 0:
            num_public = 1
        total = max(1, num_public + max(0, num_private))
        octets = _rand_sample = random.sample(range(1, 255), total)

        services_choices = [
            {22: "ssh"},
            {80: "http"},
            {22: "ssh", 80: "http"},
            {22: "ssh", 3389: "rdp"},
            {21: "ftp", 22: "ssh"},
        ]
        os_choices = [
            "Ubuntu 22.04 LTS",
            "Debian 11",
            "RouterOS 6.49",
            "Windows Server 2019",
            "Alpine Linux 3.18",
        ]

        network: Dict[str, Any] = {}
        public_octets = octets[:num_public]
        codename_octet = random.choice(public_octets) if codename else None

        for octet in public_octets:
            ip = f"192.168.0.{octet}"
            name = f"host-{octet}"
            os_choice = random.choice(os_choices)
            banner = f"{os_choice}"
            home_message = (
                f"Codename: {codename}" if octet == codename_octet
                else "This is not the correct server. Try another host."
            )
            network[ip] = {
                "name": name,
                "public": True,
                "services": random.choice(services_choices),
                "os": os_choice,
                "latency": round(random.uniform(0.5, 20.0), 1),
                "banner": banner,
                "shell_hint": "Check the home directory for clues.",
                "home_message": home_message,
            }

        for octet in octets[num_public:]:
            ip = f"192.168.0.{octet}"
            name = f"priv-{octet}"
            passwd = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            auth_user = random.choice(["admin", "root", "dbadmin", "administrator", "user"])
            os_choice = random.choice(os_choices)
            banner = f"{os_choice}"
            network[ip] = {
                "name": name,
                "public": False,
                "password": passwd,
                "auth_user": auth_user,
                "services": random.choice(services_choices),
                "os": os_choice,
                "latency": round(random.uniform(0.5, 50.0), 1),
                "banner": banner,
                "shell_hint": "Authentication required.",
                "home_message": "This is not the correct server. Try another host.",
            }

        self.network = network
