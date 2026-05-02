import datetime
import random
import string
from typing import Dict, Any

SECRET_FOLDER_NAME = "CodeName"

# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk(name, parent, content, owner="root", permissions=None):
    return Node(name, parent, is_dir=False, content=content,
                owner=owner, permissions=permissions or "rw-r--r--")


def _rand_ip():
    return f"192.168.{random.randint(0,2)}.{random.randint(1,254)}"


def _rand_date(days_back=365):
    d = datetime.datetime.now() - datetime.timedelta(days=random.randint(0, days_back))
    return d.strftime("%Y-%m-%d")


def _rand_log_lines(service="syslog", count=8):
    users = ["root", "admin", "ubuntu", "deploy"]
    msgs = {
        "sshd": [
            "Accepted password for {u} from {ip} port {p}",
            "Failed password for {u} from {ip} port {p}",
            "pam_unix(sshd:session): session opened for user {u}",
            "Disconnected from {ip}: Bye Bye",
            "Server listening on 0.0.0.0 port 22",
        ],
        "nginx": [
            '{ip} - - [{date}] "GET /index.html HTTP/1.1" 200 1234',
            '{ip} - - [{date}] "POST /api/login HTTP/1.1" 401 89',
            '{ip} - - [{date}] "GET /robots.txt HTTP/1.1" 404 0',
            "Starting nginx: nginx.",
        ],
        "cron": [
            "CRON[{pid}]: ({u}) CMD (/usr/bin/backup.sh)",
            "CRON[{pid}]: ({u}) CMD (find /tmp -mtime +7 -delete)",
        ],
        "kernel": [
            "EXT4-fs (sda1): mounted filesystem",
            "NET: Registered protocol family 2",
            "random: crng init done",
        ],
        "syslog": [
            "kernel: EXT4-fs (sda1): mounted filesystem",
            "sshd[{pid}]: Server listening on 0.0.0.0 port 22",
            "cron[{pid}]: ({u}) CMD (/usr/bin/backup.sh)",
            "systemd[1]: Starting OpenSSH server daemon...",
            "kernel: random: crng init done",
        ],
    }
    all_msgs = []
    for svc_msgs in msgs.values():
        all_msgs.extend(svc_msgs)
    lines = []
    for _ in range(count):
        tmpl = random.choice(all_msgs)
        line = tmpl.format(
            u=random.choice(users), ip=_rand_ip(),
            p=random.randint(40000, 65000), date=_rand_date(30),
            pid=random.randint(1000, 9999),
        )
        dt = datetime.datetime.now() - datetime.timedelta(
            hours=random.randint(0, 72), minutes=random.randint(0, 59))
        ts = dt.strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} {service}[{random.randint(100,9999)}]: {line}")
    return "\n".join(sorted(lines))


def _rand_crontab(user):
    jobs = [
        "0 * * * * /usr/bin/python3 /opt/scripts/monitor.py >> /var/log/monitor.log 2>&1",
        "*/15 * * * * /usr/local/bin/health_check.sh",
        "0 2 * * * /usr/bin/find /tmp -mtime +7 -delete",
        f"30 3 * * 0 /usr/bin/backup.sh /home/{user} /backup/weekly",
        "@reboot /opt/services/startup.sh",
        "5 4 * * 1 /usr/sbin/logrotate /etc/logrotate.conf",
    ]
    header = f"# Crontab for {user}\n# m h dom mon dow command\n"
    return header + "\n".join(random.sample(jobs, random.randint(2, 4)))


def _rand_config(service):
    configs = {
        "nginx": (
            "server {\n"
            "    listen 80;\n"
            "    server_name _;\n\n"
            "    root /var/www/html;\n"
            "    index index.html index.htm;\n\n"
            "    access_log /var/log/nginx/access.log;\n"
            "    error_log  /var/log/nginx/error.log warn;\n\n"
            "    location / {\n"
            "        try_files $uri $uri/ =404;\n"
            "    }\n\n"
            "    location /api/ {\n"
            "        proxy_pass http://127.0.0.1:8080;\n"
            "        proxy_set_header Host $host;\n"
            "    }\n"
            "}"
        ),
        "mysql": (
            "[mysqld]\n"
            "user            = mysql\n"
            "pid-file        = /var/run/mysqld/mysqld.pid\n"
            "socket          = /var/run/mysqld/mysqld.sock\n"
            "port            = 3306\n"
            "basedir         = /usr\n"
            "datadir         = /var/lib/mysql\n"
            "bind-address    = 127.0.0.1\n"
            "max_connections = 100\n"
            "log_error       = /var/log/mysql/error.log\n"
        ),
        "sshd": (
            "Port 22\n"
            "Protocol 2\n"
            "HostKey /etc/ssh/ssh_host_rsa_key\n"
            "PermitRootLogin no\n"
            "PasswordAuthentication yes\n"
            "ChallengeResponseAuthentication no\n"
            "UsePAM yes\n"
            "X11Forwarding no\n"
            "PrintMotd no\n"
            f"AllowUsers {random.choice(['admin','ubuntu','deploy','student'])}\n"
            "Subsystem sftp /usr/lib/openssh/sftp-server\n"
        ),
    }
    return configs.get(service, f"# {service} configuration\n# Generated automatically\n")


def _rand_script(name):
    scripts = {
        "backup.sh": (
            "#!/bin/bash\n# Automated backup script\nset -euo pipefail\n\n"
            "BACKUP_DIR=/backup/$(date +%Y%m%d)\nmkdir -p \"$BACKUP_DIR\"\n\n"
            "echo \"[$(date)] Starting backup...\"\n"
            "tar -czf \"$BACKUP_DIR/home.tar.gz\" /home/\n"
            "tar -czf \"$BACKUP_DIR/etc.tar.gz\" /etc/\n"
            "echo \"[$(date)] Backup complete: $BACKUP_DIR\"\n"
        ),
        "monitor.py": (
            "#!/usr/bin/env python3\n\"\"\"Simple health-check monitor.\"\"\"\n"
            "import subprocess, datetime, sys\n\n"
            "SERVICES = ['nginx', 'sshd', 'cron']\n\n"
            "for svc in SERVICES:\n"
            "    r = subprocess.run(['systemctl', 'is-active', svc],\n"
            "                       capture_output=True, text=True)\n"
            "    status = r.stdout.strip()\n"
            "    ts = datetime.datetime.now().isoformat()\n"
            "    print(f'[{ts}] {svc}: {status}')\n"
        ),
        "deploy.sh": (
            "#!/bin/bash\n# Deployment script\nset -e\n\n"
            "APP_DIR=/opt/app\nREPO_URL=https://git.internal/team/app.git\n\n"
            "echo \"Pulling latest changes...\"\n"
            "cd \"$APP_DIR\"\ngit pull origin main\n"
            "pip3 install -r requirements.txt --quiet\n"
            "systemctl restart app\necho \"Deploy complete.\"\n"
        ),
        "health_check.sh": (
            "#!/bin/bash\n# Health check\nfor svc in nginx ssh; do\n"
            "    systemctl is-active --quiet $svc && echo \"$svc: OK\" || echo \"$svc: FAILED\"\ndone\n"
        ),
    }
    return scripts.get(name, f"#!/bin/bash\n# {name}\necho 'done'\n")


DISTRO_PKGS = {
    "Ubuntu 22.04 LTS":  ["nginx/1.18.0", "openssh-server/8.9p1", "python3/3.10.6", "curl/7.81.0"],
    "Ubuntu 24.04 LTS":  ["nginx/1.24.0", "openssh-server/9.6p1", "python3/3.12.3", "curl/8.5.0"],
    "Debian 11":         ["nginx/1.18.0", "openssh-server/8.4p1", "python3/3.9.2",  "curl/7.74.0"],
    "Debian 12":         ["nginx/1.22.1", "openssh-server/9.2p1", "python3/3.11.2", "curl/7.88.1"],
    "Linux Mint 21":     ["apache2/2.4.52", "openssh-server/8.9p1", "python3/3.10.6", "curl/7.81.0"],
    "Alpine Linux 3.18": ["nginx/1.24.0", "openssh/9.3p2",        "python3/3.11.6", "curl/8.1.2"],
    "Rocky Linux 9":     ["httpd/2.4.53", "openssh-server/8.7p1", "python3/3.9.14", "curl/7.76.1"],
    "AlmaLinux 9":       ["httpd/2.4.53", "openssh-server/8.7p1", "python3/3.9.14", "curl/7.76.1"],
}


def build_remote_filesystem(env, host_info: dict, auth_user: str, codename: str = "", is_target: bool = False):
    """Populate a fresh VirtualEnvironment with a realistic per-host filesystem."""
    root      = env.root
    os_name   = host_info.get("os", "Ubuntu 22.04 LTS")
    host_type = host_info.get("host_type", "generic")

    # --- /etc ---
    etc = root.children["etc"]
    etc.children["hostname"]   = _mk("hostname",   etc, env.hostname + "\n")
    etc.children["os-release"] = _mk("os-release", etc,
        f'NAME="{os_name}"\nVERSION="1.0"\nID={os_name.split()[0].lower()}\n'
        f'PRETTY_NAME="{os_name}"\nHOME_URL="https://www.example.com"\n')
    etc.children["passwd"] = _mk("passwd", etc,
        f"root:x:0:0:root:/root:/bin/bash\n"
        f"{auth_user}:x:1000:1000:{auth_user.capitalize()}:/home/{auth_user}:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n",
        permissions="rw-r--r--")
    etc.children["shadow"] = _mk("shadow", etc,
        f"root:!:19000:0:99999:7:::\n{auth_user}:$6$salt$hashedpassword:19000:0:99999:7:::\n",
        permissions="rw-------")
    etc.children["hosts"] = _mk("hosts", etc,
        f"127.0.0.1   localhost\n127.0.1.1   {env.hostname}\n"
        f"::1         localhost ip6-localhost\n192.168.0.1   gateway-router\n")
    etc.children["resolv.conf"] = _mk("resolv.conf", etc,
        "nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch internal.example.com\n")

    ssh_dir = Node("ssh", etc, is_dir=True)
    etc.children["ssh"] = ssh_dir
    ssh_dir.children["sshd_config"] = _mk("sshd_config", ssh_dir, _rand_config("sshd"))

    crond = Node("cron.d", etc, is_dir=True)
    etc.children["cron.d"] = crond
    crond.children[f"{auth_user}-tasks"] = _mk(
        f"{auth_user}-tasks", crond, _rand_crontab(auth_user))

    # --- /var ---
    var     = root.children["var"]
    var_log = var.children.get("log") or Node("log", var, is_dir=True)
    var.children["log"] = var_log
    var_log.children["syslog"]   = _mk("syslog",   var_log, _rand_log_lines("syslog",  10), owner="syslog")
    var_log.children["auth.log"] = _mk("auth.log", var_log, _rand_log_lines("sshd",    8),  owner="syslog")
    var_log.children["kern.log"] = _mk("kern.log", var_log, _rand_log_lines("kernel",  6),  owner="syslog")

    if host_type in ("web", "generic"):
        nginx_log = Node("nginx", var_log, is_dir=True)
        var_log.children["nginx"] = nginx_log
        nginx_log.children["access.log"] = _mk("access.log", nginx_log, _rand_log_lines("nginx", 12))
        nginx_log.children["error.log"]  = _mk("error.log",  nginx_log, "")

    if host_type == "web":
        www      = Node("www",  var, is_dir=True)
        html_dir = Node("html", www, is_dir=True, owner="www-data")
        var.children["www"] = www
        www.children["html"] = html_dir
        html_dir.children["index.html"] = _mk("index.html", html_dir,
            f"<!DOCTYPE html>\n<html><head><title>{env.hostname}</title></head>\n"
            f"<body><h1>Welcome to {env.hostname}</h1><p>Service running.</p></body></html>\n",
            owner="www-data")
        html_dir.children["robots.txt"] = _mk("robots.txt", html_dir,
            "User-agent: *\nDisallow: /admin/\n", owner="www-data")

    backups = Node("backups", var, is_dir=True)
    var.children["backups"] = backups
    for i in range(random.randint(1, 3)):
        d = (datetime.datetime.now() - datetime.timedelta(days=i * 7)).strftime("%Y%m%d")
        backups.children[f"home_{d}.tar.gz"] = _mk(
            f"home_{d}.tar.gz", backups,
            f"# compressed archive placeholder – {d}\n", owner="root")

    var_lib = Node("lib", var, is_dir=True)
    var.children["lib"] = var_lib
    dpkg = Node("dpkg", var_lib, is_dir=True)
    var_lib.children["dpkg"] = dpkg
    pkgs = DISTRO_PKGS.get(os_name, DISTRO_PKGS["Ubuntu 22.04 LTS"])
    dpkg.children["status"] = _mk("status", dpkg,
        "# Installed packages (excerpt)\n" +
        "\n".join(f"Package: {p.split('/')[0]}\nVersion: {p.split('/')[1]}\nStatus: install ok installed\n"
                  for p in pkgs))

    # --- /opt ---
    opt = root.children.get("opt") or Node("opt", root, is_dir=True)
    root.children["opt"] = opt
    scripts_dir = Node("scripts", opt, is_dir=True)
    opt.children["scripts"] = scripts_dir
    for sname in random.sample(["backup.sh", "monitor.py", "deploy.sh", "health_check.sh"],
                               random.randint(2, 3)):
        scripts_dir.children[sname] = _mk(sname, scripts_dir, _rand_script(sname),
                                          permissions="rwxr-xr-x")

    if host_type == "db":
        mysql_dir = Node("mysql", opt, is_dir=True)
        opt.children["mysql"] = mysql_dir
        mysql_dir.children["my.cnf"] = _mk("my.cnf", mysql_dir, _rand_config("mysql"), owner="mysql")
        schemas = Node("schemas", mysql_dir, is_dir=True)
        mysql_dir.children["schemas"] = schemas
        schemas.children["app_db.sql"] = _mk("app_db.sql", schemas,
            "-- app database schema\n"
            "CREATE TABLE users (id INT PRIMARY KEY AUTO_INCREMENT,\n"
            "  username VARCHAR(64), email VARCHAR(128), created_at DATETIME);\n"
            "CREATE TABLE sessions (token CHAR(64) PRIMARY KEY, user_id INT, expires DATETIME);\n")

    # --- /home/<user> ---
    home_root = root.children.get("home") or Node("home", root, is_dir=True)
    root.children["home"] = home_root
    home_root.children = {}

    user_home = Node(auth_user, home_root, is_dir=True, owner=auth_user)
    user_home.children = {}
    home_root.children[auth_user] = user_home

    user_home.children[".bashrc"] = _mk(".bashrc", user_home,
        f"# ~/.bashrc for {auth_user}\nexport PS1='\\u@\\h:\\w\\$ '\n"
        "alias ll='ls -la'\nalias la='ls -A'\nalias l='ls -CF'\n",
        owner=auth_user, permissions="rw-r--r--")

    history_cmds = random.sample([
        "ls -la", "cd /var/log", "cat syslog", "ps aux", "df -h", "top",
        f"cd /opt/scripts", "bash backup.sh",
        f"ssh root@{_rand_ip()}", "tail -f /var/log/auth.log",
        "grep 'Failed' /var/log/auth.log", "netstat -tlnp", "free -h",
        "uptime", "cat /etc/passwd", "id", "whoami", "ls -la /opt/scripts",
        "crontab -l", "find / -name '*.log' 2>/dev/null",
    ], random.randint(8, 15))
    user_home.children[".bash_history"] = _mk(".bash_history", user_home,
        "\n".join(history_cmds) + "\n", owner=auth_user, permissions="rw-------")

    # hint / readme
    hint_msg = host_info.get("home_message", "This is not the correct server. Try another host.")
    user_home.children["readme.md"] = _mk("readme.md", user_home, hint_msg, owner=auth_user)
    if is_target:
        folder_hint_msg = f"The codename is hidden in the folder: {SECRET_FOLDER_NAME}\nGood luck finding it. \n"
        user_home.children["hint.txt"] = _mk("hint.txt", user_home, folder_hint_msg, owner=auth_user)

    # documents subdir
    docs = Node("documents", user_home, is_dir=True, owner=auth_user)
    user_home.children["documents"] = docs
    docs.children["notes.txt"] = _mk("notes.txt", docs,
        f"Personal notes – {_rand_date(30)}\n\n"
        "- Review server configs\n- Check backup logs\n"
        f"- Meeting with team on {_rand_date(10)}\n", owner=auth_user)

    # randomly add a second subdir for variety
    if random.random() < 0.6:
        extra_name = random.choice(["work", "config", "logs", "tmp_files"])
        extra = Node(extra_name, user_home, is_dir=True, owner=auth_user)
        user_home.children[extra_name] = extra
        extra.children["info.txt"] = _mk("info.txt", extra,
            f"# {extra_name}\nManaged by {auth_user}\nLast updated: {_rand_date(60)}\n",
            owner=auth_user)

    # --- /tmp ---
    tmp = root.children.get("tmp") or Node("tmp", root, is_dir=True, permissions="rwxrwxrwx")
    root.children["tmp"] = tmp
    for _ in range(random.randint(0, 3)):
        fname = f"tmp_{random.randint(10000,99999)}"
        tmp.children[fname] = _mk(fname, tmp, "", owner=auth_user)

    # --- Codename challenge files (target host only) ---
    if is_target and codename:
        _plant_codename_files(root, user_home, auth_user, codename)


def _plant_codename_files(root: Node, user_home: Node, auth_user: str, codename: str):
    """
    Plant the codename challenge on the target host:
      <parent>/<CODENAME>Folder/readme.txt   – visible clue
      <parent>/<CODENAME>Folder/.codename    – hidden secret file
    The folder is placed at a random spot in the filesystem.
    """
    folder_name = f"{SECRET_FOLDER_NAME}"

    candidates = [user_home]
    for child in list(user_home.children.values()):
        if child.is_dir:
            candidates.append(child)

    opt = root.children.get("opt")
    if opt:
        for child in list(opt.children.values()):
            if child.is_dir:
                candidates.append(child)

    tmp = root.children.get("tmp")
    if tmp:
        candidates.append(tmp)

    chosen = random.choice(candidates)

    cn_folder = Node(folder_name, chosen, is_dir=True, owner=auth_user)
    cn_folder.children = {}

    cn_folder.children["readme.txt"] = _mk("readme.txt", cn_folder,
        f"You found the right directory.\n\n"
        f"The codename file is hidden somewhere in this folder.\n"
        f"Look carefully — hidden files start with a dot (.)\n\n"
        f"Try:  ls -la\n",
        owner=auth_user)

    cn_folder.children[".codename"] = _mk(".codename", cn_folder,
        f"CODENAME: {codename}\n\n"
        f"Congratulations — you found the secret file.\n"
        f"Record this codename and report back.\n",
        owner=auth_user, permissions="rw-------")

    chosen.children[folder_name] = cn_folder


# ---------------------------------------------------------------------------
# VirtualEnvironment
# ---------------------------------------------------------------------------

def _rand_kernel():
    patch = random.randint(0, 30)
    minor = random.choice([15, 16, 17, 18, 19])
    major = random.choice([5, 6])
    return (f"{major}.{minor}.{patch}-{random.randint(1,9)}-generic "
            f"#{random.randint(30,99)}-Ubuntu SMP x86_64")


def _build_motd(hostname: str, os_name: str) -> str:
    kernel = _rand_kernel()
    pkgs   = random.randint(200, 800)
    sec    = random.randint(0, pkgs)
    load   = round(random.uniform(0.01, 2.5), 2)
    disk   = random.randint(15, 70)
    disk_g = random.randint(20, 200)
    mem    = random.randint(20, 85)
    swap   = random.randint(0, 30)
    procs  = random.randint(80, 300)
    users  = random.randint(0, 3)
    now    = datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
    eth_ip = _rand_ip()
    lines = [
        f"Welcome to {os_name} (GNU/Linux {kernel.split()[0]})",
        "",
        " * Documentation: https://help.ubuntu.com",
        " * Management:    https://landscape.canonical.com",
        " * Support:       https://ubuntu.com/pro",
        "",
        f"System information as of {now}",
        "",
        f"  System load:     {load}",
        f"  Usage of /:      {disk}% of {disk_g}GB",
        f"  Memory usage:    {mem}%",
        f"  Swap usage:      {swap}%",
        f"  Processes:       {procs}",
        f"  Users logged in: {users}",
        "",
        f"  IPv4 address for eth0: {eth_ip}",
        "",
        f" * Kernel: {kernel}",
        f" * {pkgs} packages can be updated.",
        f"   {sec} of these are security updates.",
    ]
    return "\n".join(lines)


class VirtualEnvironment:
    def __init__(self, codename: str = "", num_public: int = 5, num_private: int = 3):
        self.root = Node("/", permissions="rwxr-xr-x")
        self.cwd  = self.root
        self.vars = {
            "HOME": "/home/student",
            "USER": "student",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
        }
        self.user     = "student"
        self.hostname = "cyber-lab"
        self.last_exit_code = 0

        home = Node("home", self.root, permissions="rwxr-xr-x")
        etc  = Node("etc",  self.root, permissions="rwxr-xr-x")
        bin_ = Node("bin",  self.root, permissions="rwxr-xr-x")
        var  = Node("var",  self.root, permissions="rwxr-xr-x")
        tmp  = Node("tmp",  self.root, permissions="rwxrwxrwx")
        usr  = Node("usr",  self.root, permissions="rwxr-xr-x")
        opt  = Node("opt",  self.root, permissions="rwxr-xr-x")

        self.root.children = {
            "home": home, "etc": etc, "bin": bin_, "var": var,
            "tmp": tmp, "usr": usr, "opt": opt,
        }

        student_home = Node("student", home, is_dir=True, owner="student")
        home.children["student"] = student_home
        student_home.children = {
            "notes.txt": Node("notes.txt", student_home, False,
                              "hint: scan the network\ntarget range: 192.168.0.0/24"),
            "readme.md": Node("readme.md", student_home, False,
                              "# Cyber Lab\n\nObjective: find the codename hidden on the network.\n\n"
                              "## Steps\n1. Scan the network (try: scan)\n"
                              "2. Ping hosts to check latency (try: ping <ip>)\n"
                              "3. Connect to a host (try: connect <ip>)\n"
                              "4. Explore the filesystem\n5. Find the hidden codename"),
            "scripts": Node("scripts", student_home, True),
        }
        student_home.children["scripts"].children = {}

        etc.children["hosts"] = Node("hosts", etc, False,
            "127.0.0.1 localhost\n::1       localhost\n"
            "192.168.0.1 gateway-router\n")
        etc.children["passwd"] = Node("passwd", etc, False,
            "root:x:0:0:root:/root:/bin/bash\n"
            "student:x:1000:1000::/home/student:/bin/bash\n",
            permissions="rw-r--r--")
        etc.children["os-release"] = Node("os-release", etc, False,
            'NAME="Cyber Lab Linux"\nVERSION="1.0"\nID=cyberlab\n'
            'PRETTY_NAME="Cyber Lab Linux 1.0"')

        var.children["log"] = Node("log", var, True)
        var.children["log"].children = {
            "syslog": Node("syslog", var.children["log"], False, _rand_log_lines("syslog", 12))
        }

        self.generate_random_network(codename, num_public, num_private)
        self.authenticated = set()

    def generate_random_network(self, codename: str, num_public: int = 5, num_private: int = 3):
        if num_public <= 0:
            num_public = 1
        total   = max(1, num_public + max(0, num_private))
        octets  = random.sample(range(2, 254), total)

        services_pool = [
            {22: "ssh"},
            {80: "http"},
            {22: "ssh", 80: "http"},
            {22: "ssh", 3389: "rdp"},
            {21: "ftp", 22: "ssh"},
            {22: "ssh", 443: "https"},
            {22: "ssh", 80: "http", 3306: "mysql"},
            {80: "http", 443: "https"},
        ]
        os_choices = [
            "Ubuntu 22.04 LTS", "Ubuntu 24.04 LTS", "Debian 11", "Debian 12",
            "Linux Mint 21", "Alpine Linux 3.18", "Rocky Linux 9", "AlmaLinux 9",
        ]
        host_types = ["web", "db", "generic"]

        network: Dict[str, Any] = {}
        public_octets  = octets[:num_public]
        private_octets = octets[num_public:]
        codename_octet = random.choice(public_octets) if codename else None

        for octet in public_octets:
            ip        = f"192.168.0.{octet}"
            host_type = random.choice(host_types)
            os_choice = random.choice(os_choices)
            is_target = (octet == codename_octet and bool(codename))
            prefix    = {"web": "web", "db": "db", "generic": "host"}[host_type]
            name      = f"{prefix}-{octet}"

            home_message = (
                "You are on the correct server.\n\n"
                "The codename is hidden somewhere on this host.\n"
                "Explore the filesystem carefully\n"
                if is_target
                else "This is not the correct server. Try another host."
            )

            network[ip] = {
                "name":         name,
                "public":       True,
                "services":     random.choice(services_pool),
                "os":           os_choice,
                "host_type":    host_type,
                "latency":      round(random.uniform(0.4, 15.0), 2),
                "banner":       _build_motd(name, os_choice),
                "shell_hint":   "Check the home directory for clues.",
                "home_message": home_message,
                "is_target":    is_target,
                "codename":     codename if is_target else "",
                "uptime_days":  random.randint(1, 400),
                "kernel":       _rand_kernel(),
                "ssh_version":  f"SSH-2.0-OpenSSH_{random.choice(['8.9p1','9.2p1','9.6p1','8.4p1'])}",
            }

        for octet in private_octets:
            ip          = f"192.168.0.{octet}"
            host_type   = random.choice(host_types)
            os_choice   = random.choice(os_choices)
            is_honeypot = random.random() < 0.2
            passwd      = None if is_honeypot else "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(10))
            auth_user   = random.choice(["admin", "root", "dbadmin", "administrator", "deploy"])
            name        = f"priv-{octet}"

            network[ip] = {
                "name":         name,
                "public":       False,
                "password":     passwd,
                "auth_user":    auth_user,
                "services":     random.choice(services_pool),
                "os":           os_choice,
                "host_type":    host_type,
                "latency":      round(random.uniform(0.4, 50.0), 2),
                "banner":       _build_motd(name, os_choice),
                "shell_hint":   "Authentication required." if not is_honeypot else "Access restricted.",
                "home_message": "This is not the correct server. Try another host.",
                "is_target":    False,
                "codename":     "",
                "uptime_days":  random.randint(1, 400),
                "kernel":       _rand_kernel(),
                "ssh_version":  f"SSH-2.0-OpenSSH_{random.choice(['8.9p1','9.2p1','9.6p1','8.4p1'])}",
            }

        self.network = network
