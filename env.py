import datetime
import random
import string
from typing import Dict, Any
from utils import (random_password, choose_random_directory, rand_config, rand_script, rand_kernel,
                   collect_candidate_dirs, rand_ip, rand_data, rand_log_lines, rand_crontab)
from virtual_shell import VirtualEnvironment

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


def build_remote_filesystem(
        env: VirtualEnvironment,
        host_info: dict,
        auth_user: str,
        codename: str = "",
        is_target: bool = False
):
    """Populate a fresh VirtualEnvironment with a realistic per-host filesystem."""
    root      = env.root
    os_name   = host_info.get("os", "Ubuntu 22.04 LTS")
    host_type = host_info.get("host_type", "generic")

    # ── /etc ─────────────────────────────────────────────────────────────
    etc = root.children["etc"]
    etc.children["hostname"]    = _mk("hostname",    etc, env.hostname + "\n")
    etc.children["os-release"]  = _mk("os-release",  etc,
        f'NAME="{os_name}"\nVERSION="1.0"\nID={os_name.split()[0].lower()}\n'
        f'PRETTY_NAME="{os_name}"\nHOME_URL="https://www.example.com"\n')
    etc.children["passwd"]      = _mk("passwd", etc,
        f"root:x:0:0:root:/root:/bin/bash\n"
        f"{auth_user}:x:1000:1000:{auth_user.capitalize()}:/home/{auth_user}:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        permissions="rw-r--r--")
    etc.children["shadow"]      = _mk("shadow", etc,
        f"root:!:19000:0:99999:7:::\n{auth_user}:$6$salt$hashedpassword:19000:0:99999:7:::\n",
        permissions="rw-------")
    etc.children["group"]       = _mk("group", etc,
        f"root:x:0:\ndaemon:x:1:\nsudo:x:27:{auth_user}\n{auth_user}:x:1000:\n",
        permissions="rw-r--r--")
    etc.children["hosts"]       = _mk("hosts", etc,
        f"127.0.0.1   localhost\n127.0.1.1   {env.hostname}\n"
        f"::1         localhost ip6-localhost\n192.168.0.1   gateway-router\n")
    etc.children["resolv.conf"] = _mk("resolv.conf", etc,
        "nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch internal.example.com\n")
    etc.children["timezone"]    = _mk("timezone", etc, "UTC\n")
    etc.children["environment"] = _mk("environment", etc,
        'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\nLANG="en_US.UTF-8"\n')
    etc.children["fstab"]       = _mk("fstab", etc,
        "UUID=abc123  /      ext4  errors=remount-ro  0  1\n"
        "UUID=def456  /boot  ext4  defaults           0  2\n"
        "UUID=ghi789  none   swap  sw                 0  0\n")
    etc.children["motd"]        = _mk("motd", etc,
        f"Welcome to {env.hostname}. Authorised access only.\n")
    etc.children["issue"]       = _mk("issue", etc,
        f"{os_name} \\n \\l\n")

    # /etc/ssh/
    etc_ssh = Node("ssh", etc, is_dir=True)
    etc.children["ssh"] = etc_ssh
    etc_ssh.children["sshd_config"]     = _mk("sshd_config",     etc_ssh, rand_config("sshd"))
    etc_ssh.children["ssh_config"]      = _mk("ssh_config",      etc_ssh,
        "Host *\n    ServerAliveInterval 60\n    StrictHostKeyChecking ask\n")
    etc_ssh.children["ssh_host_rsa_key"] = _mk("ssh_host_rsa_key", etc_ssh,
        "-----BEGIN RSA PRIVATE KEY-----\n[redacted]\n-----END RSA PRIVATE KEY-----\n",
        permissions="rw-------")
    etc_ssh.children["ssh_host_rsa_key.pub"] = _mk("ssh_host_rsa_key.pub", etc_ssh,
        f"ssh-rsa AAAAB3NzaC1yc2EAAAA root@{env.hostname}\n")

    # /etc/cron.d/
    crond = Node("cron.d", etc, is_dir=True)
    etc.children["cron.d"] = crond
    crond.children[f"{auth_user}-tasks"] = _mk(f"{auth_user}-tasks", crond,
                                                rand_crontab(auth_user))
    crond.children["logrotate"] = _mk("logrotate", crond,
        "0 0 * * * root /usr/sbin/logrotate /etc/logrotate.conf\n")

    # /etc/logrotate.d/
    logrotated = Node("logrotate.d", etc, is_dir=True)
    etc.children["logrotate.d"] = logrotated
    logrotated.children["syslog"] = _mk("syslog", logrotated,
        "/var/log/syslog {\n  weekly\n  rotate 7\n  compress\n  missingok\n}\n")
    if host_type in ("web", "generic"):
        logrotated.children["nginx"] = _mk("nginx", logrotated,
            "/var/log/nginx/*.log {\n  daily\n  rotate 14\n  compress\n"
            "  postrotate\n    nginx -s reopen\n  endscript\n}\n")

    # /etc/apt/ (Debian/Ubuntu) or /etc/yum.repos.d/ (RHEL/Rocky/Alma)
    if "Ubuntu" in os_name or "Debian" in os_name or "Mint" in os_name:
        apt_dir = Node("apt", etc, is_dir=True)
        etc.children["apt"] = apt_dir
        apt_dir.children["sources.list"] = _mk("sources.list", apt_dir,
            "deb http://archive.ubuntu.com/ubuntu jammy main restricted\n"
            "deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted\n"
            "deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n")
        sources_d = Node("sources.list.d", apt_dir, is_dir=True)
        apt_dir.children["sources.list.d"] = sources_d
    else:
        yum_dir = Node("yum.repos.d", etc, is_dir=True)
        etc.children["yum.repos.d"] = yum_dir
        yum_dir.children["base.repo"] = _mk("base.repo", yum_dir,
            "[base]\nname=Base\nbaseurl=http://mirror.example.com/base\nenabled=1\ngpgcheck=1\n")

    # /etc/profile.d/
    profiled = Node("profile.d", etc, is_dir=True)
    etc.children["profile.d"] = profiled
    profiled.children["bash_completion.sh"] = _mk("bash_completion.sh", profiled,
        "[ -r /usr/share/bash-completion/bash_completion ] && "
        ". /usr/share/bash-completion/bash_completion\n", permissions="rwxr-xr-x")

    # /etc/network/ or /etc/sysconfig/network-scripts/ depending on OS
    if "Ubuntu" in os_name or "Debian" in os_name or "Mint" in os_name or "Alpine" in os_name:
        net_cfg = Node("network", etc, is_dir=True)
        etc.children["network"] = net_cfg
        net_cfg.children["interfaces"] = _mk("interfaces", net_cfg,
            "auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet dhcp\n")
    else:
        sysconfig = Node("sysconfig", etc, is_dir=True)
        etc.children["sysconfig"] = sysconfig
        net_scripts = Node("network-scripts", sysconfig, is_dir=True)
        sysconfig.children["network-scripts"] = net_scripts
        net_scripts.children["ifcfg-eth0"] = _mk("ifcfg-eth0", net_scripts,
            "DEVICE=eth0\nBOOTPROTO=dhcp\nONBOOT=yes\n")

    # ── /var ─────────────────────────────────────────────────────────────
    var     = root.children["var"]
    var_log = var.children.get("log") or Node("log", var, is_dir=True)
    var_lib  = Node("lib",  var, is_dir=True)
    var_run  = Node("run",  var, is_dir=True)
    var_spool = Node("spool", var, is_dir=True)
    var_cache = Node("cache", var, is_dir=True)
    var.children.update({
        "log": var_log, "lib": var_lib, "run": var_run,
        "spool": var_spool, "cache": var_cache,
    })

    # /var/log/
    var_log.children["syslog"]   = _mk("syslog",   var_log, rand_log_lines("syslog",  12), owner="syslog")
    var_log.children["auth.log"] = _mk("auth.log", var_log, rand_log_lines("sshd",    10), owner="syslog")
    var_log.children["kern.log"] = _mk("kern.log", var_log, rand_log_lines("kernel",   6), owner="syslog")
    var_log.children["dpkg.log"] = _mk("dpkg.log", var_log,
        f"{rand_data(30)} startup archives dpkg\n"
        f"{rand_data(30)} install openssh-server:amd64 <none> 1:8.9p1\n",
        owner="root")
    var_log.children["boot.log"] = _mk("boot.log", var_log,
        "[ OK ] Started OpenSSH Server Daemon.\n"
        "[ OK ] Reached target Network.\n"
        "[ OK ] Started System Logging Service.\n", owner="root")
    var_log.children["lastlog"]  = _mk("lastlog",  var_log, "# binary lastlog\n", owner="root")
    var_log.children["faillog"]  = _mk("faillog",  var_log, "# binary faillog\n", owner="root")

    apt_log = Node("apt", var_log, is_dir=True)
    var_log.children["apt"] = apt_log
    apt_log.children["history.log"] = _mk("history.log", apt_log,
        f"Start-Date: {rand_data(60)}\n"
        "Commandline: apt-get install -y openssh-server\n"
        "Install: openssh-server\nEnd-Date: done\n")
    apt_log.children["term.log"] = _mk("term.log", apt_log,
        "Reading package lists... Done\nBuilding dependency tree... Done\n")

    if host_type in ("web", "generic"):
        nginx_log = Node("nginx", var_log, is_dir=True)
        var_log.children["nginx"] = nginx_log
        nginx_log.children["access.log"] = _mk("access.log", nginx_log, rand_log_lines("nginx", 15))
        nginx_log.children["error.log"]  = _mk("error.log",  nginx_log, "")

    if host_type == "db":
        mysql_log = Node("mysql", var_log, is_dir=True)
        var_log.children["mysql"] = mysql_log
        mysql_log.children["error.log"] = _mk("error.log", mysql_log,
            f"{rand_data(5)} [Note] mysqld: ready for connections.\n"
            f"{rand_data(3)} [Warning] Aborted connection from {rand_ip()}\n")

    # /var/lib/
    dpkg = Node("dpkg", var_lib, is_dir=True)
    var_lib.children["dpkg"] = dpkg
    dpkg_info = Node("info", dpkg, is_dir=True)
    dpkg.children["info"] = dpkg_info
    pkgs = DISTRO_PKGS.get(os_name, DISTRO_PKGS["Ubuntu 22.04 LTS"])
    dpkg.children["status"] = _mk("status", dpkg,
        "# Installed packages (excerpt)\n" +
        "\n".join(f"Package: {p.split('/')[0]}\nVersion: {p.split('/')[1]}\n"
                  f"Status: install ok installed\n"
                  for p in pkgs))
    dpkg.children["lock"] = _mk("lock", dpkg, "", owner="root", permissions="rw-------")

    systemd_lib = Node("systemd", var_lib, is_dir=True)
    var_lib.children["systemd"] = systemd_lib
    units_dir = Node("units", systemd_lib, is_dir=True)
    systemd_lib.children["units"] = units_dir

    # /var/run/
    var_run.children["sshd.pid"] = _mk("sshd.pid", var_run, f"{random.randint(500,9999)}\n", owner="root")
    var_run.children["utmp"]     = _mk("utmp",     var_run, "# binary utmp\n", owner="root")

    # /var/spool/
    cron_spool = Node("cron", var_spool, is_dir=True, permissions="rwx--x--x", owner="root")
    var_spool.children["cron"] = cron_spool
    crontabs = Node("crontabs", cron_spool, is_dir=True, permissions="rwx------", owner="root")
    cron_spool.children["crontabs"] = crontabs
    crontabs.children[auth_user] = _mk(auth_user, crontabs,
        rand_crontab(auth_user), owner=auth_user, permissions="rw-------")
    mail_spool = Node("mail", var_spool, is_dir=True)
    var_spool.children["mail"] = mail_spool
    mail_spool.children[auth_user] = _mk(auth_user, mail_spool,
        f"From root@{env.hostname} {rand_data(10)}\n"
        "Subject: System notification\n\nScheduled maintenance complete.\n",
        owner=auth_user)

    # /var/cache/
    apt_cache = Node("apt", var_cache, is_dir=True)
    var_cache.children["apt"] = apt_cache
    apt_cache.children["pkgcache.bin"] = _mk("pkgcache.bin", apt_cache,
        "# apt package cache (binary)\n", permissions="rw-r--r--")

    if host_type == "web":
        # /var/www/
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
        html_dir.children[".htaccess"] = _mk(".htaccess", html_dir,
            "Options -Indexes\nAllowOverride None\n", owner="www-data", permissions="rw-r--r--")
        admin_dir = Node("admin", html_dir, is_dir=True, owner="www-data", permissions="rwx------")
        html_dir.children["admin"] = admin_dir
        admin_dir.children["index.php"] = _mk("index.php", admin_dir,
            "<?php\n// Admin panel — restricted access\nsession_start();\n"
            "if (!isset($_SESSION['admin'])) { header('Location: /login'); exit; }\n?>",
            owner="www-data", permissions="rw-------")

    # /var/backups/
    backups = Node("backups", var, is_dir=True)
    var.children["backups"] = backups
    for i in range(random.randint(1, 3)):
        d = (datetime.datetime.now() - datetime.timedelta(days=i * 7)).strftime("%Y%m%d")
        backups.children[f"home_{d}.tar.gz"] = _mk(f"home_{d}.tar.gz", backups,
            f"# compressed archive placeholder – {d}\n", owner="root")
    backups.children["etc_latest.tar.gz"] = _mk("etc_latest.tar.gz", backups,
        f"# etc backup placeholder\n", owner="root")

    # ── /opt ─────────────────────────────────────────────────────────────
    opt = root.children.get("opt") or Node("opt", root, is_dir=True)
    root.children["opt"] = opt

    # /opt/scripts/
    scripts_dir = Node("scripts", opt, is_dir=True)
    opt.children["scripts"] = scripts_dir
    for sname in random.sample(["backup.sh", "monitor.py", "deploy.sh", "health_check.sh"],
                               random.randint(2, 4)):
        scripts_dir.children[sname] = _mk(sname, scripts_dir, rand_script(sname),
                                           permissions="rwxr-xr-x")
    scripts_dir.children["README"] = _mk("README", scripts_dir,
        "# Operational scripts\nRun with appropriate privileges.\n"
        "backup.sh   – full home+etc backup\n"
        "monitor.py  – service health check\n"
        "deploy.sh   – pull and restart app\n")

    # /opt/services/
    services_dir = Node("services", opt, is_dir=True)
    opt.children["services"] = services_dir
    services_dir.children["startup.sh"] = _mk("startup.sh", services_dir,
        "#!/bin/bash\necho 'Starting services...'\nsystemctl start nginx\n"
        "systemctl start sshd\necho 'Done.'\n", permissions="rwxr-xr-x")
    services_dir.children["shutdown.sh"] = _mk("shutdown.sh", services_dir,
        "#!/bin/bash\necho 'Stopping services...'\nsystemctl stop nginx\necho 'Done.'\n",
        permissions="rwxr-xr-x")

    if host_type == "db":
        # /opt/mysql/
        mysql_dir = Node("mysql", opt, is_dir=True)
        opt.children["mysql"] = mysql_dir
        mysql_dir.children["my.cnf"] = _mk("my.cnf", mysql_dir,
            rand_config("mysql"), owner="mysql")
        schemas = Node("schemas", mysql_dir, is_dir=True)
        mysql_dir.children["schemas"] = schemas
        schemas.children["app_db.sql"] = _mk("app_db.sql", schemas,
            "-- app database schema\n"
            "CREATE TABLE users (\n  id INT PRIMARY KEY AUTO_INCREMENT,\n"
            "  username VARCHAR(64),\n  email VARCHAR(128),\n"
            "  password_hash CHAR(60),\n  created_at DATETIME\n);\n\n"
            "CREATE TABLE sessions (\n  token CHAR(64) PRIMARY KEY,\n"
            "  user_id INT,\n  expires DATETIME\n);\n\n"
            "CREATE TABLE audit_log (\n  id INT PRIMARY KEY AUTO_INCREMENT,\n"
            "  user_id INT,\n  action VARCHAR(128),\n  ts DATETIME\n);\n")
        mysql_dir.children["credentials.txt"] = _mk("credentials.txt", mysql_dir,
            f"# DB credentials — keep private\n"
            f"DB_USER=app_user\nDB_PASS={''.join(random.choices(string.ascii_letters+string.digits, k=12))}\n"
            f"DB_NAME=app_db\nDB_HOST=127.0.0.1\n",
            owner=auth_user, permissions="rw-------")
        dumps = Node("dumps", mysql_dir, is_dir=True)
        mysql_dir.children["dumps"] = dumps
        d = rand_data(14)
        dumps.children[f"app_db_{d}.sql.gz"] = _mk(f"app_db_{d}.sql.gz", dumps,
            "# mysqldump binary placeholder\n", owner=auth_user)

    if host_type == "web":
        # /opt/app/
        app_dir = Node("app", opt, is_dir=True)
        opt.children["app"] = app_dir
        app_dir.children["requirements.txt"] = _mk("requirements.txt", app_dir,
            "flask==3.0.0\ngunicorn==21.2.0\nrequests==2.31.0\nsqlalchemy==2.0.23\n")
        app_dir.children[".env"] = _mk(".env", app_dir,
            f"SECRET_KEY={''.join(random.choices(string.ascii_letters+string.digits, k=32))}\n"
            "DEBUG=False\nDATABASE_URL=sqlite:///app.db\n",
            owner=auth_user, permissions="rw-------")
        app_dir.children["app.py"] = _mk("app.py", app_dir,
            "from flask import Flask\napp = Flask(__name__)\n\n"
            "@app.route('/')\ndef index():\n    return 'Hello, World!'\n\n"
            "if __name__ == '__main__':\n    app.run()\n")
        src_dir = Node("src", app_dir, is_dir=True)
        app_dir.children["src"] = src_dir
        src_dir.children["models.py"] = _mk("models.py", src_dir,
            "# Database models\nfrom sqlalchemy import Column, Integer, String\n")
        src_dir.children["routes.py"] = _mk("routes.py", src_dir,
            "# Route definitions\nfrom flask import Blueprint\nmain = Blueprint('main', __name__)\n")

    # ── /usr ─────────────────────────────────────────────────────────────
    usr = root.children.get("usr") or Node("usr", root, is_dir=True)
    root.children["usr"] = usr
    usr_bin   = Node("bin",   usr, is_dir=True)
    usr_sbin  = Node("sbin",  usr, is_dir=True, permissions="rwxr-x---", owner="root")
    usr_lib   = Node("lib",   usr, is_dir=True)
    usr_share = Node("share", usr, is_dir=True)
    usr_local = Node("local", usr, is_dir=True)
    usr.children.update({
        "bin": usr_bin, "sbin": usr_sbin,
        "lib": usr_lib, "share": usr_share, "local": usr_local,
    })

    # /usr/bin/ – commonly expected tools
    for cmd in ["python3","pip3","curl","wget","git","nano","vim","ssh","scp",
                "rsync","tar","gzip","diff","make","gcc","perl","find","grep",
                "awk","sed","htop","ps","kill","nmap","base64","openssl","jq",
                "md5sum","sha256sum","env","tee","xargs","tr","column","bc"]:
        usr_bin.children[cmd] = _mk(cmd, usr_bin, f"# {cmd}", owner="root", permissions="rwxr-xr-x")

    # /usr/sbin/
    for cmd in ["sshd","nginx","cron","rsyslogd","logrotate","useradd",
                "userdel","visudo","iptables","tcpdump"]:
        usr_sbin.children[cmd] = _mk(cmd, usr_sbin, f"# {cmd}", owner="root", permissions="rwxr-x---")

    # /usr/lib/ – key subdirs
    openssh_lib = Node("openssh", usr_lib, is_dir=True)
    usr_lib.children["openssh"] = openssh_lib
    openssh_lib.children["sftp-server"] = _mk("sftp-server", openssh_lib,
        "# sftp-server binary", permissions="rwxr-xr-x")
    python_lib = Node("python3", usr_lib, is_dir=True)
    usr_lib.children["python3"] = python_lib
    python_lib.children["dist-packages"] = Node("dist-packages", python_lib, is_dir=True)
    ssl_lib = Node("ssl", usr_lib, is_dir=True)
    usr_lib.children["ssl"] = ssl_lib
    ssl_lib.children["certs"] = Node("certs", ssl_lib, is_dir=True)

    # /usr/share/
    doc_dir = Node("doc", usr_share, is_dir=True)
    usr_share.children["doc"] = doc_dir
    for pkg in ["bash", "openssh-server", "nginx", "python3"]:
        pd = Node(pkg, doc_dir, is_dir=True)
        doc_dir.children[pkg] = pd
        pd.children["changelog.gz"] = _mk("changelog.gz", pd, "# changelog binary")
        pd.children["README"] = _mk("README", pd,
            f"# {pkg}\nSee upstream documentation for details.\n")
    man_dir = Node("man", usr_share, is_dir=True)
    usr_share.children["man"] = man_dir
    for sec in ["man1", "man5", "man8"]:
        man_dir.children[sec] = Node(sec, man_dir, is_dir=True)
    bash_comp = Node("bash-completion", usr_share, is_dir=True)
    usr_share.children["bash-completion"] = bash_comp
    bash_comp.children["bash_completion"] = _mk("bash_completion", bash_comp,
        "# bash completion master script\n")

    # /usr/local/
    local_bin = Node("bin", usr_local, is_dir=True)
    usr_local.children["bin"] = local_bin
    local_bin.children["health_check.sh"] = _mk("health_check.sh", local_bin,
        "#!/bin/bash\nfor svc in nginx sshd cron; do\n"
        "    systemctl is-active --quiet $svc && echo \"$svc: OK\" || echo \"$svc: FAILED\"\ndone\n",
        permissions="rwxr-xr-x")
    local_etc = Node("etc", usr_local, is_dir=True)
    usr_local.children["etc"] = local_etc
    local_lib = Node("lib", usr_local, is_dir=True)
    usr_local.children["lib"] = local_lib

    # ── /home/<user> ─────────────────────────────────────────────────────
    home_root = root.children.get("home") or Node("home", root, is_dir=True)
    root.children["home"] = home_root
    home_root.children = {}

    user_home = Node(auth_user, home_root, is_dir=True, owner=auth_user)
    user_home.children = {}
    home_root.children[auth_user] = user_home

    # dotfiles
    user_home.children[".bashrc"] = _mk(".bashrc", user_home,
        f"# ~/.bashrc for {auth_user}\nexport PS1='\\u@\\h:\\w\\$ '\n"
        "alias ll='ls -la'\nalias la='ls -A'\nalias l='ls -CF'\n"
        "export EDITOR=nano\n", owner=auth_user, permissions="rw-r--r--")
    user_home.children[".bash_profile"] = _mk(".bash_profile", user_home,
        "[ -f ~/.bashrc ] && . ~/.bashrc\n", owner=auth_user, permissions="rw-r--r--")
    user_home.children[".profile"] = _mk(".profile", user_home,
        'export PATH="$HOME/bin:$PATH"\n', owner=auth_user, permissions="rw-r--r--")

    history_cmds = random.sample([
        "ls -la", "cd /var/log", "cat syslog", "ps aux", "df -h", "top",
        "cd /opt/scripts", "bash backup.sh",
        f"ssh root@{rand_ip()}", "tail -f /var/log/auth.log",
        "grep 'Failed' /var/log/auth.log", "netstat -tlnp", "free -h",
        "uptime", "cat /etc/passwd", "id", "whoami", "ls -la /opt/scripts",
        "crontab -l", "find / -name '*.log' 2>/dev/null",
        "cat /etc/cron.d/*", "systemctl status nginx", "journalctl -xe",
        f"cat /opt/mysql/credentials.txt", "nano /etc/ssh/sshd_config",
    ], random.randint(10, 18))
    user_home.children[".bash_history"] = _mk(".bash_history", user_home,
        "\n".join(history_cmds) + "\n", owner=auth_user, permissions="rw-------")

    # .ssh/
    ssh_home = Node(".ssh", user_home, is_dir=True, owner=auth_user, permissions="rwx------")
    user_home.children[".ssh"] = ssh_home
    ssh_home.children["authorized_keys"] = _mk("authorized_keys", ssh_home,
        f"ssh-rsa AAAAB3NzaC1yc2EAAAA {auth_user}@workstation\n",
        owner=auth_user, permissions="rw-------")
    ssh_home.children["known_hosts"] = _mk("known_hosts", ssh_home,
        f"192.168.0.1 ecdsa-sha2-nistp256 AAAA{rand_data()}\n",
        owner=auth_user, permissions="rw-------")

    # readme / hint
    hint_msg = host_info.get("home_message", "This is not the correct server. Try another host.")
    user_home.children["readme.md"] = _mk("readme.md", user_home, hint_msg, owner=auth_user)
    if is_target:
        folder_hint_msg = (
            f"The codename is hidden in the folder: {SECRET_FOLDER_NAME}\n"
            "Good luck finding it.\n")
        user_home.children["hint.txt"] = _mk("hint.txt", user_home,
                                              folder_hint_msg, owner=auth_user)

    # ~/documents/
    docs = Node("documents", user_home, is_dir=True, owner=auth_user)
    user_home.children["documents"] = docs
    docs.children["notes.txt"] = _mk("notes.txt", docs,
        f"Personal notes – {rand_data(30)}\n\n"
        "- Review server configs\n- Check backup logs\n"
        f"- Meeting with team on {rand_data(10)}\n", owner=auth_user)
    docs.children["server_inventory.txt"] = _mk("server_inventory.txt", docs,
        f"# Server Inventory – updated {rand_data(7)}\n"
        f"192.168.0.1  gateway-router  core\n"
        f"{rand_ip()}  app-server     web\n"
        f"{rand_ip()}  db-primary     db\n", owner=auth_user)

    # ~/bin/
    user_bin = Node("bin", user_home, is_dir=True, owner=auth_user)
    user_home.children["bin"] = user_bin
    user_bin.children["check_disk.sh"] = _mk("check_disk.sh", user_bin,
        "#!/bin/bash\ndf -h | awk 'NR>1 {print $5, $6}' | sort -rn | head -5\n",
        owner=auth_user, permissions="rwxr-xr-x")

    # randomly add extra subdir
    if random.random() < 0.65:
        extra_name = random.choice(["work", "config", "logs", "tmp_files", "projects"])
        extra = Node(extra_name, user_home, is_dir=True, owner=auth_user)
        user_home.children[extra_name] = extra
        extra.children["info.txt"] = _mk("info.txt", extra,
            f"# {extra_name}\nManaged by {auth_user}\nLast updated: {rand_data(60)}\n",
            owner=auth_user)
        if extra_name == "projects" or random.random() < 0.3:
            sub = Node("archive", extra, is_dir=True, owner=auth_user)
            extra.children["archive"] = sub
            sub.children[f"backup_{rand_data(90)}.tar.gz"] = _mk(
                f"backup_{rand_data(90)}.tar.gz", sub,
                "# archive placeholder\n", owner=auth_user)

    # ── /tmp ─────────────────────────────────────────────────────────────
    tmp = root.children.get("tmp") or Node("tmp", root, is_dir=True, permissions="rwxrwxrwx")
    root.children["tmp"] = tmp
    for _ in range(random.randint(1, 4)):
        fname = f"tmp_{random.randint(10000,99999)}"
        tmp.children[fname] = _mk(fname, tmp, "", owner=auth_user)
    tmp.children[".X11-unix"] = Node(".X11-unix", tmp, is_dir=True,
                                      permissions="rwxrwxrwt", owner="root")
    # Occasionally a stale session file — realistic noise
    if random.random() < 0.4:
        tmp.children[f"sess_{random.randint(100000,999999)}"] = _mk(
            f"sess_{random.randint(100000,999999)}", tmp,
            "# stale session data\n", owner=auth_user, permissions="rw-------")

    # ── /proc stub ───────────────────────────────────────────────────────
    proc = root.children.get("proc") or Node("proc", root, is_dir=True,
                                              permissions="r-xr-xr-x", owner="root")
    root.children["proc"] = proc
    proc.children["version"]  = _mk("version", proc,
        f"Linux version {rand_kernel()} (gcc version 11.3.0)\n",
        owner="root", permissions="r--r--r--")
    proc.children["uptime"]   = _mk("uptime", proc,
        f"{random.randint(100,9999)}.{random.randint(0,99)} "
        f"{random.randint(50,4999)}.{random.randint(0,99)}\n",
        owner="root", permissions="r--r--r--")
    proc.children["cpuinfo"]  = _mk("cpuinfo", proc,
        "processor\t: 0\nvendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz\n"
        "cpu MHz\t\t: 2600.000\ncache size\t: 20480 KB\n",
        owner="root", permissions="r--r--r--")
    proc.children["meminfo"]  = _mk("meminfo", proc,
        f"MemTotal:       {random.randint(2,16)*1024*1024} kB\n"
        f"MemFree:        {random.randint(100,2000)*1024} kB\n"
        "SwapTotal:      2097152 kB\nSwapFree:       2097152 kB\n",
        owner="root", permissions="r--r--r--")
    proc.children["mounts"]   = _mk("mounts", proc,
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "proc /proc proc rw,nosuid 0 0\n"
        "sysfs /sys sysfs rw,nosuid 0 0\n",
        owner="root", permissions="r--r--r--")

    # ── Codename challenge files (target host only) ────────────────────
    if is_target and codename:
        print("env", env.challenge_level)
        _plant_codename_files(root, user_home, auth_user, codename, env.challenge_level)


def _plant_codename_files(root: Node, user_home: Node, auth_user: str, codename: str, level: int):
    """
    Plant the codename challenge on the target host:
      <parent>/<CODENAME>Folder/readme.txt   – visible clue
      <parent>/<CODENAME>Folder/.codename    – hidden secret file
    The folder is placed at a random spot in the filesystem.
    """
    if level == 1:
        folder_name = f"{SECRET_FOLDER_NAME}"

        chosen = choose_random_directory(collect_candidate_dirs(root, user_home))

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

def _build_motd(hostname: str, os_name: str) -> str:
    kernel = rand_kernel()
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
    eth_ip = rand_ip()
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
        self.challenge_level = 0
        self.vars = {
            "HOME":  "/home/student",
            "USER":  "student",
            "SHELL": "/bin/bash",
            "PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM":  "xterm-256color",
            "LANG":  "en_US.UTF-8",
        }
        self.user     = "student"
        self.hostname = "cyber-lab"
        self.codename = codename
        self.last_exit_code = 0

        # ── Top-level directories ──────────────────────────────────────────
        home = Node("home", self.root, permissions="rwxr-xr-x")
        etc  = Node("etc",  self.root, permissions="rwxr-xr-x")
        bin_ = Node("bin",  self.root, permissions="rwxr-xr-x")
        sbin = Node("sbin", self.root, permissions="rwxr-x---", owner="root")
        var  = Node("var",  self.root, permissions="rwxr-xr-x")
        tmp  = Node("tmp",  self.root, permissions="rwxrwxrwx")
        usr  = Node("usr",  self.root, permissions="rwxr-xr-x")
        opt  = Node("opt",  self.root, permissions="rwxr-xr-x")
        proc = Node("proc", self.root, permissions="r-xr-xr-x")
        dev  = Node("dev",  self.root, permissions="rwxr-xr-x")
        run  = Node("run",  self.root, permissions="rwxr-xr-x")

        self.root.children = {
            "home": home, "etc": etc, "bin": bin_, "sbin": sbin,
            "var": var, "tmp": tmp, "usr": usr, "opt": opt,
            "proc": proc, "dev": dev, "run": run,
        }

        # ── /bin ──────────────────────────────────────────────────────────
        for cmd in ["bash","sh","ls","cat","echo","cp","mv","rm","mkdir",
                    "rmdir","chmod","chown","ln","grep","sed","awk","find",
                    "sort","uniq","cut","wc","head","tail","date","pwd",
                    "sleep","true","false","ping","hostname","uname"]:
            bin_.children[cmd] = _mk(cmd, bin_, f"# {cmd} binary", owner="root",
                                     permissions="rwxr-xr-x")

        # ── /sbin ─────────────────────────────────────────────────────────
        for cmd in ["iptables","ip","ifconfig","route","reboot","shutdown",
                    "fdisk","fsck","mount","umount","sysctl","useradd",
                    "userdel","groupadd","visudo"]:
            sbin.children[cmd] = _mk(cmd, sbin, f"# {cmd} binary", owner="root",
                                     permissions="rwxr-x---")

        # ── /etc ──────────────────────────────────────────────────────────
        etc.children["hostname"]   = _mk("hostname",   etc, "cyber-lab\n")
        etc.children["hosts"]      = _mk("hosts", etc,
            "127.0.0.1   localhost\n127.0.1.1   cyber-lab\n"
            "::1         localhost ip6-localhost\n192.168.0.1 gateway-router\n")
        etc.children["passwd"]     = _mk("passwd", etc,
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
            "student:x:1000:1000:Student User:/home/student:/bin/bash\n",
            permissions="rw-r--r--")
        etc.children["shadow"]     = _mk("shadow", etc,
            "root:!:19000:0:99999:7:::\nstudent:$6$salt$hashed:19000:0:99999:7:::\n",
            permissions="rw-------", owner="root")
        etc.children["group"]      = _mk("group", etc,
            "root:x:0:\ndaemon:x:1:\nsudo:x:27:student\nstudent:x:1000:\n",
            permissions="rw-r--r--")
        etc.children["shells"]     = _mk("shells", etc,
            "/bin/sh\n/bin/bash\n/bin/dash\n/usr/bin/zsh\n")
        etc.children["timezone"]   = _mk("timezone",   etc, "UTC\n")
        etc.children["os-release"] = _mk("os-release", etc,
            'NAME="Cyber Lab Linux"\nVERSION="1.0"\nID=cyberlab\n'
            'PRETTY_NAME="Cyber Lab Linux 1.0"\nHOME_URL="https://cyberlab.example.com"\n')
        etc.children["resolv.conf"] = _mk("resolv.conf", etc,
            "nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch lab.internal\n")
        etc.children["fstab"]      = _mk("fstab", etc,
            "# <file system>  <mount point>  <type>  <options>         <dump>  <pass>\n"
            "UUID=abc123       /              ext4    errors=remount-ro  0       1\n"
            "UUID=def456       /boot          ext4    defaults           0       2\n"
            "UUID=ghi789       none           swap    sw                 0       0\n")
        etc.children["issue"]      = _mk("issue", etc,
            "Cyber Lab Linux 1.0 \\n \\l\n")
        etc.children["motd"]       = _mk("motd", etc,
            "Welcome to Cyber Lab Linux.\nAuthorised access only.\n")
        etc.children["environment"] = _mk("environment", etc,
            'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n'
            'LANG="en_US.UTF-8"\n')
        etc.children["logrotate.conf"] = _mk("logrotate.conf", etc,
            "weekly\nrotate 4\ncreate\ncompress\ninclude /etc/logrotate.d\n")

        # /etc/ssh/
        etc_ssh = Node("ssh", etc, is_dir=True)
        etc.children["ssh"] = etc_ssh
        etc_ssh.children["sshd_config"] = _mk("sshd_config", etc_ssh,
            "Port 22\nProtocol 2\nPermitRootLogin no\nPasswordAuthentication yes\n"
            "ChallengeResponseAuthentication no\nUsePAM yes\nX11Forwarding no\n"
            "PrintMotd no\nSubsystem sftp /usr/lib/openssh/sftp-server\n"
            f"AllowUsers student\n")
        etc_ssh.children["ssh_config"] = _mk("ssh_config", etc_ssh,
            "Host *\n    ServerAliveInterval 60\n    ServerAliveCountMax 3\n")

        # /etc/cron.d/
        crond = Node("cron.d", etc, is_dir=True)
        etc.children["cron.d"] = crond
        crond.children["student-tasks"] = _mk("student-tasks", crond,
            rand_crontab("student"))
        crond.children["syslog"] = _mk("syslog", crond,
            "# Rotate logs daily\n0 0 * * * root /usr/sbin/logrotate /etc/logrotate.conf\n")

        # /etc/apt/
        apt_dir = Node("apt", etc, is_dir=True)
        etc.children["apt"] = apt_dir
        apt_dir.children["sources.list"] = _mk("sources.list", apt_dir,
            "deb http://archive.ubuntu.com/ubuntu jammy main restricted\n"
            "deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted\n"
            "deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n")
        apt_sources_d = Node("sources.list.d", apt_dir, is_dir=True)
        apt_dir.children["sources.list.d"] = apt_sources_d

        # /etc/network/
        network_dir = Node("network", etc, is_dir=True)
        etc.children["network"] = network_dir
        interfaces_dir = Node("interfaces.d", network_dir, is_dir=True)
        network_dir.children["interfaces"] = _mk("interfaces", network_dir,
            "# This file describes the network interfaces\n"
            "source /etc/network/interfaces.d/*\n\n"
            "auto lo\niface lo inet loopback\n\n"
            "auto eth0\niface eth0 inet dhcp\n")
        network_dir.children["interfaces.d"] = interfaces_dir

        # /etc/logrotate.d/
        logrotated = Node("logrotate.d", etc, is_dir=True)
        etc.children["logrotate.d"] = logrotated
        logrotated.children["syslog"] = _mk("syslog", logrotated,
            "/var/log/syslog {\n  weekly\n  rotate 7\n  compress\n  missingok\n  notifempty\n}\n")
        logrotated.children["nginx"] = _mk("nginx", logrotated,
            "/var/log/nginx/*.log {\n  daily\n  rotate 14\n  compress\n"
            "  sharedscripts\n  postrotate\n    nginx -s reopen\n  endscript\n}\n")

        # /etc/profile.d/
        profiled = Node("profile.d", etc, is_dir=True)
        etc.children["profile.d"] = profiled
        profiled.children["bash_completion.sh"] = _mk("bash_completion.sh", profiled,
            "# bash completion\n[ -r /usr/share/bash-completion/bash_completion ] && "
            ". /usr/share/bash-completion/bash_completion\n", permissions="rwxr-xr-x")
        profiled.children["color_prompt.sh"] = _mk("color_prompt.sh", profiled,
            "export PS1='\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\n",
            permissions="rwxr-xr-x")

        # ── /var ──────────────────────────────────────────────────────────
        var_log  = Node("log",  var, is_dir=True)
        var_lib  = Node("lib",  var, is_dir=True)
        var_run  = Node("run",  var, is_dir=True)
        var_spool = Node("spool", var, is_dir=True)
        var_cache = Node("cache", var, is_dir=True)
        var_tmp   = Node("tmp",  var, is_dir=True, permissions="rwxrwxrwx")
        var.children.update({
            "log": var_log, "lib": var_lib, "run": var_run,
            "spool": var_spool, "cache": var_cache, "tmp": var_tmp,
        })

        # /var/log/
        var_log.children["syslog"]    = _mk("syslog",    var_log, rand_log_lines("syslog",  15), owner="syslog")
        var_log.children["auth.log"]  = _mk("auth.log",  var_log, rand_log_lines("sshd",    10), owner="syslog")
        var_log.children["kern.log"]  = _mk("kern.log",  var_log, rand_log_lines("kernel",   8), owner="syslog")
        var_log.children["dpkg.log"]  = _mk("dpkg.log",  var_log,
            f"2024-01-15 02:30:01 startup archives dpkg\n"
            f"2024-01-15 02:30:01 install openssh-server:amd64 <none> 1:8.9p1\n"
            f"2024-01-15 02:30:02 status installed openssh-server:amd64 1:8.9p1\n",
            owner="root")
        var_log.children["boot.log"]  = _mk("boot.log",  var_log,
            "[ OK ] Started OpenSSH Server Daemon.\n"
            "[ OK ] Reached target Network.\n"
            "[ OK ] Started System Logging Service.\n", owner="root")
        var_log.children["lastlog"]   = _mk("lastlog",   var_log, "# binary lastlog\n", owner="root",
                                             permissions="rw-r--r--")
        var_log.children["faillog"]   = _mk("faillog",   var_log, "# binary faillog\n", owner="root",
                                             permissions="rw-r--r--")

        # /var/log/apt/
        apt_log = Node("apt", var_log, is_dir=True)
        var_log.children["apt"] = apt_log
        apt_log.children["history.log"] = _mk("history.log", apt_log,
            f"Start-Date: {rand_data(30)}\n"
            "Commandline: apt-get install -y openssh-server nginx\n"
            "Install: openssh-server, nginx\nEnd-Date: done\n")
        apt_log.children["term.log"] = _mk("term.log", apt_log,
            "Reading package lists... Done\nBuilding dependency tree... Done\n"
            "The following packages will be installed:\n  nginx openssh-server\n")

        # /var/lib/
        dpkg_dir = Node("dpkg", var_lib, is_dir=True)
        var_lib.children["dpkg"] = dpkg_dir
        dpkg_info = Node("info", dpkg_dir, is_dir=True)
        dpkg_dir.children["info"] = dpkg_info
        dpkg_dir.children["status"] = _mk("status", dpkg_dir,
            "# Installed packages (excerpt)\n"
            "Package: bash\nVersion: 5.2.15\nStatus: install ok installed\nArchitecture: amd64\n\n"
            "Package: openssh-server\nVersion: 1:8.9p1\nStatus: install ok installed\nArchitecture: amd64\n\n"
            "Package: nginx\nVersion: 1.18.0\nStatus: install ok installed\nArchitecture: amd64\n\n"
            "Package: python3\nVersion: 3.10.6\nStatus: install ok installed\nArchitecture: amd64\n\n"
            "Package: curl\nVersion: 7.81.0\nStatus: install ok installed\nArchitecture: amd64\n")
        dpkg_dir.children["lock"] = _mk("lock", dpkg_dir, "", owner="root", permissions="rw-------")

        var_lib.children["systemd"] = Node("systemd", var_lib, is_dir=True)
        systemd_units = Node("units", var_lib.children["systemd"], is_dir=True)
        var_lib.children["systemd"].children["units"] = systemd_units

        # /var/spool/
        cron_spool = Node("cron", var_spool, is_dir=True, permissions="rwx--x--x", owner="root")
        var_spool.children["cron"] = cron_spool
        crontabs = Node("crontabs", cron_spool, is_dir=True, permissions="rwx------", owner="root")
        cron_spool.children["crontabs"] = crontabs
        crontabs.children["student"] = _mk("student", crontabs,
            rand_crontab("student"), owner="student", permissions="rw-------")
        mail_spool = Node("mail", var_spool, is_dir=True)
        var_spool.children["mail"] = mail_spool
        mail_spool.children["student"] = _mk("student", mail_spool,
            "From root@cyber-lab Mon Jan 15 09:00:00 2024\n"
            "Subject: Welcome to Cyber Lab\n\n"
            "Welcome to Cyber Lab Linux. Your account is ready.\n", owner="student")

        # /var/cache/
        apt_cache = Node("apt", var_cache, is_dir=True)
        var_cache.children["apt"] = apt_cache
        apt_cache.children["pkgcache.bin"] = _mk("pkgcache.bin", apt_cache,
            "# apt package cache (binary)\n", permissions="rw-r--r--")

        # /var/run → symlink to /run (represented as dir)
        var_run.children["sshd.pid"] = _mk("sshd.pid", var_run, "1234\n", owner="root")
        var_run.children["utmp"]     = _mk("utmp",     var_run, "# binary utmp\n", owner="root",
                                           permissions="rw-r--r--")

        # ── /usr ──────────────────────────────────────────────────────────
        usr_bin   = Node("bin",   usr, is_dir=True)
        usr_sbin  = Node("sbin",  usr, is_dir=True, permissions="rwxr-x---", owner="root")
        usr_lib   = Node("lib",   usr, is_dir=True)
        usr_share = Node("share", usr, is_dir=True)
        usr_local = Node("local", usr, is_dir=True)
        usr_include = Node("include", usr, is_dir=True)
        usr.children.update({
            "bin": usr_bin, "sbin": usr_sbin, "lib": usr_lib,
            "share": usr_share, "local": usr_local, "include": usr_include,
        })

        # /usr/bin/ — common tools
        for cmd in ["python3","python3.10","pip3","curl","wget","git","nano","vim",
                    "ssh","scp","sftp","rsync","tar","gzip","gunzip","zip","unzip",
                    "man","less","more","which","whereis","locate","file","strings",
                    "diff","patch","make","gcc","g++","perl","ruby","node","npm",
                    "htop","top","ps","kill","killall","pkill","pgrep","nmap","netcat",
                    "nc","tcpdump","strace","ltrace","ldd","objdump","readelf",
                    "base64","xxd","hexdump","md5sum","sha256sum","openssl","gpg",
                    "env","printenv","tee","xargs","tr","column","jq","bc"]:
            usr_bin.children[cmd] = _mk(cmd, usr_bin, f"# {cmd} binary",
                                        owner="root", permissions="rwxr-xr-x")

        # /usr/sbin/
        for cmd in ["sshd","nginx","apache2","cron","rsyslogd","logrotate",
                    "useradd","userdel","usermod","groupadd","chpasswd",
                    "visudo","iptables","ip6tables","nft","tcpdump","wireshark"]:
            usr_sbin.children[cmd] = _mk(cmd, usr_sbin, f"# {cmd} binary",
                                         owner="root", permissions="rwxr-x---")

        # /usr/lib/
        python_lib = Node("python3", usr_lib, is_dir=True)
        usr_lib.children["python3"] = python_lib
        python_lib.children["dist-packages"] = Node("dist-packages", python_lib, is_dir=True)
        ssl_lib = Node("ssl", usr_lib, is_dir=True)
        usr_lib.children["ssl"] = ssl_lib
        ssl_lib.children["certs"] = Node("certs", ssl_lib, is_dir=True)
        openssh_lib = Node("openssh", usr_lib, is_dir=True)
        usr_lib.children["openssh"] = openssh_lib
        openssh_lib.children["sftp-server"] = _mk("sftp-server", openssh_lib,
            "# sftp-server binary", permissions="rwxr-xr-x")

        # /usr/share/
        man_dir = Node("man", usr_share, is_dir=True)
        usr_share.children["man"] = man_dir
        for section in ["man1", "man5", "man8"]:
            s = Node(section, man_dir, is_dir=True)
            man_dir.children[section] = s
        doc_dir = Node("doc", usr_share, is_dir=True)
        usr_share.children["doc"] = doc_dir
        for pkg in ["bash", "openssh-server", "nginx"]:
            pd = Node(pkg, doc_dir, is_dir=True)
            doc_dir.children[pkg] = pd
            pd.children["changelog.gz"] = _mk("changelog.gz", pd, "# changelog binary")
            pd.children["README"] = _mk("README", pd,
                f"# {pkg}\nSee /usr/share/doc/{pkg} for documentation.\n")
        common_licenses = Node("common-licenses", usr_share, is_dir=True)
        usr_share.children["common-licenses"] = common_licenses
        common_licenses.children["GPL-2"] = _mk("GPL-2", common_licenses,
            "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n")
        common_licenses.children["MIT"] = _mk("MIT", common_licenses,
            "MIT License\nPermission is hereby granted, free of charge...\n")
        bash_comp = Node("bash-completion", usr_share, is_dir=True)
        usr_share.children["bash-completion"] = bash_comp
        bash_comp.children["bash_completion"] = _mk("bash_completion", bash_comp,
            "# bash completion master script\n")

        # /usr/local/
        local_bin  = Node("bin",  usr_local, is_dir=True)
        local_sbin = Node("sbin", usr_local, is_dir=True)
        local_lib  = Node("lib",  usr_local, is_dir=True)
        local_etc  = Node("etc",  usr_local, is_dir=True)
        usr_local.children.update({
            "bin": local_bin, "sbin": local_sbin,
            "lib": local_lib, "etc": local_etc,
        })
        local_bin.children["health_check.sh"] = _mk("health_check.sh", local_bin,
            "#!/bin/bash\nfor svc in nginx sshd cron; do\n"
            "    systemctl is-active --quiet $svc && echo \"$svc: OK\" || echo \"$svc: FAILED\"\ndone\n",
            permissions="rwxr-xr-x")

        # ── /opt ──────────────────────────────────────────────────────────
        scripts_dir = Node("scripts", opt, is_dir=True)
        opt.children["scripts"] = scripts_dir
        scripts_dir.children["backup.sh"] = _mk("backup.sh", scripts_dir,
            rand_script("backup.sh"), permissions="rwxr-xr-x")
        scripts_dir.children["monitor.py"] = _mk("monitor.py", scripts_dir,
            rand_script("monitor.py"), permissions="rwxr-xr-x")

        services_dir = Node("services", opt, is_dir=True)
        opt.children["services"] = services_dir
        services_dir.children["startup.sh"] = _mk("startup.sh", services_dir,
            "#!/bin/bash\n# Service startup script\necho 'Starting services...'\n"
            "systemctl start nginx\nsystemctl start sshd\necho 'Done.'\n",
            permissions="rwxr-xr-x")
        services_dir.children["README"] = _mk("README", services_dir,
            "# Services\nPlace service scripts here.\nRun startup.sh to initialize.\n")

        # ── /proc (stub — realistic-looking, not functional) ─────────────
        proc.children["version"]   = _mk("version", proc,
            f"Linux version {rand_kernel()} (gcc version 11.3.0)\n",
            owner="root", permissions="r--r--r--")
        proc.children["uptime"]    = _mk("uptime",  proc,
            f"{random.randint(100,9999)}.{random.randint(0,99)} "
            f"{random.randint(50,4999)}.{random.randint(0,99)}\n",
            owner="root", permissions="r--r--r--")
        proc.children["cpuinfo"]   = _mk("cpuinfo", proc,
            "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
            "model name\t: Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz\n"
            "cpu MHz\t\t: 2600.000\ncache size\t: 20480 KB\n",
            owner="root", permissions="r--r--r--")
        proc.children["meminfo"]   = _mk("meminfo", proc,
            f"MemTotal:       {random.randint(2,16)*1024*1024} kB\n"
            f"MemFree:        {random.randint(100,2000)*1024} kB\n"
            f"MemAvailable:   {random.randint(500,4000)*1024} kB\n"
            "SwapTotal:      2097152 kB\nSwapFree:       2097152 kB\n",
            owner="root", permissions="r--r--r--")
        proc.children["mounts"]    = _mk("mounts", proc,
            "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            "/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0\n",
            owner="root", permissions="r--r--r--")
        proc.children["net"]       = Node("net", proc, is_dir=True,
                                           permissions="r-xr-xr-x", owner="root")
        net_proc = proc.children["net"]
        net_proc.children["dev"] = _mk("dev", net_proc,
            "Inter-|   Receive                                             |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast"
            "|bytes    packets errs drop fifo colls carrier compressed\n"
            f"    lo: {random.randint(1000,99999)} {random.randint(10,999)} 0 0 0 0 0 0 "
            f"{random.randint(1000,99999)} {random.randint(10,999)} 0 0 0 0 0 0\n"
            f"  eth0: {random.randint(1000000,99999999)} {random.randint(1000,99999)} 0 0 0 0 0 0 "
            f"{random.randint(100000,9999999)} {random.randint(100,9999)} 0 0 0 0 0 0\n",
            owner="root", permissions="r--r--r--")

        # ── /dev (stub) ────────────────────────────────────────────────────
        for dname, perm in [("null","rw-rw-rw-"),("zero","rw-rw-rw-"),
                             ("random","rw-r--r--"),("urandom","rw-r--r--"),
                             ("tty","rw-rw-rw-"),("sda","rw-------"),
                             ("sda1","rw-------"),("sda2","rw-------")]:
            dev.children[dname] = _mk(dname, dev, f"# {dname} device",
                                      owner="root", permissions=perm)
        pts_dir = Node("pts", dev, is_dir=True, permissions="rwxr-xr-x")
        dev.children["pts"] = pts_dir
        pts_dir.children["0"] = _mk("0", pts_dir, "", permissions="rw--w----", owner="student")

        # ── /run ──────────────────────────────────────────────────────────
        run.children["sshd.pid"]   = _mk("sshd.pid",  run, "1234\n", owner="root")
        run.children["utmp"]       = _mk("utmp",       run, "# binary utmp\n", owner="root")
        run.children["lock"]       = Node("lock", run, is_dir=True, owner="root")

        # ── /tmp ──────────────────────────────────────────────────────────
        for _ in range(random.randint(1, 4)):
            fname = f"tmp_{random.randint(10000, 99999)}"
            tmp.children[fname] = _mk(fname, tmp, "", owner="student")
        tmp.children[".X11-unix"] = Node(".X11-unix", tmp, is_dir=True,
                                          permissions="rwxrwxrwt", owner="root")

        # ── /home/student ─────────────────────────────────────────────────
        self.student_home = Node("student", home, is_dir=True, owner="student")
        home.children["student"] = self.student_home
        sh = self.student_home

        sh.children[".bashrc"] = _mk(".bashrc", sh,
            "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\n"
            "alias ll='ls -la'\nalias la='ls -A'\nalias l='ls -CF'\n"
            "export EDITOR=nano\n", owner="student", permissions="rw-r--r--")
        sh.children[".bash_profile"] = _mk(".bash_profile", sh,
            "# ~/.bash_profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n",
            owner="student", permissions="rw-r--r--")
        sh.children[".profile"] = _mk(".profile", sh,
            "# ~/.profile\nexport PATH=\"$HOME/bin:$PATH\"\n",
            owner="student", permissions="rw-r--r--")
        sh.children[".bash_logout"] = _mk(".bash_logout", sh,
            "# ~/.bash_logout\nclear\n", owner="student", permissions="rw-r--r--")
        sh.children[".bash_history"] = _mk(".bash_history", sh,
            "\n".join(random.sample([
                "ls -la", "cd /var/log", "cat syslog", "ps aux", "df -h",
                "cd /opt/scripts", "ping 192.168.0.1", "scan 192.168.0",
                "connect 192.168.0.42", "cat readme.md", "help",
            ], 8)) + "\n", owner="student", permissions="rw-------")

        # .ssh/
        ssh_dir_home = Node(".ssh", sh, is_dir=True, owner="student", permissions="rwx------")
        sh.children[".ssh"] = ssh_dir_home
        ssh_dir_home.children["known_hosts"] = _mk("known_hosts", ssh_dir_home,
            f"# known hosts\n192.168.0.1 ecdsa-sha2-nistp256 AAAA{rand_data()}\n",
            owner="student", permissions="rw-------")
        ssh_dir_home.children["config"] = _mk("config", ssh_dir_home,
            "Host *\n    ServerAliveInterval 60\n    StrictHostKeyChecking ask\n",
            owner="student", permissions="rw-------")

        # ~/bin/
        student_bin = Node("bin", sh, is_dir=True, owner="student")
        sh.children["bin"] = student_bin

        # ~/downloads/
        dl = Node("downloads", sh, is_dir=True, owner="student")
        sh.children["downloads"] = dl
        dl.children["tools.tar.gz"] = _mk("tools.tar.gz", dl,
            "# placeholder archive\n", owner="student")

        self.generate_random_network(codename, num_public, num_private)
        self.authenticated = set()
        # Start the user in their home directory
        self.cwd = self.student_home

    # ------------------------------------------------------------------
    # Home directory builders
    # ------------------------------------------------------------------
    def update_random_network(self, num_public: int = 5, num_private: int = 3, codename_in_public: bool=True):
        self.generate_random_network(self.codename, num_public, num_private, codename_in_public)


    def build_default_home(self):
        """Minimal home — no level context."""
        sh = self.student_home
        sh.children = {
            "notes.txt": Node("notes.txt", sh, False,
                              "hint: scan the network\ntarget range: 192.168.0.0/24"),
            "readme.md": Node("readme.md", sh, False,
                              "# Cyber Lab\n\nObjective: find the codename hidden on the network.\n\n"
                              "## Steps\n"
                              "1. Scan the network (try: scan)\n"
                              "2. Connect to a host (try: connect <ip>)\n"
                              "3. Explore the filesystem\n"
                              "4. Find the hidden codename"),
            "scripts": Node("scripts", sh, True),
        }
        sh.children["scripts"].children = {}

    def setup_level1(self):
        """Level 1 home: guided intro — student just needs to scan and connect."""
        self.challenge_level = 1
        sh = self.student_home
        sh.children = {
            "readme.md": Node("readme.md", sh, False,
                "# Level 1 – Getting Started\n\n"
                "Welcome to the Cyber Lab.\n\n"
                "## Your mission\n"
                "A secret codename is hidden on one of the hosts in this network.\n"
                "Find it and submit it.\n\n"
                "## Hints\n"
                "- Find the correct server, connect to it and find the code word\n"
                "- The codeword is hidden in a server which isn't password protected\n"
                "- When you are connected to a server try to read first the readme.md\n"
                "- If you have problem with using the commands try help\n"
                "Good luck!\n"),
        }

    def setup_level2(self):
        """Level 2 home: less hand-holding, introduce private hosts."""
        self.challenge_level = 2

        sh = self.student_home

        # -------------------------------------------------
        # Task Description
        # -------------------------------------------------
        sh.children = {
            "Task2.md": Node(
                "Task2.md",
                sh,
                False,
                "# Task 2 – Private Hosts\n\n"
                 "The network now contains password-protected systems.\n"
                 "Your objective is to obtain valid credentials and access\n"
                 "a protected host.\n\n"
                 "Hints:\n"
                 "- Explore the filesystem carefully\n"
                 "- Some files may only be readable by privileged users\n"
                 "- Use commands like find, grep, ls, cat, and su\n"
                 "- Check common system directories\n",
                 owner="student",
                 permissions="rw-r--r--"
            )
        }

        # -------------------------------------------------
        # Create /etc/network_pwd
        # Contains credentials for protected hosts
        # -------------------------------------------------
        self.rebuild_network_pwd()

    def setup_level3(self):
        """Level 3 home: minimal hints — student is on their own."""
        self.challenge_level = 3

        sh = self.student_home
        sh.children = {
            "readme.md": Node("readme.md", sh, False,
                "# Level 3 – Expert Mode\n\n"
                "No hints this time. You know what to do.\n\n"
                "Find the codename.\n"),
            ".notes": Node(".notes", sh, False,
                "# Private notes\n"
                "Don't forget: always check hidden files and subdirectories.\n",
                permissions="rw-------", owner="student"),
        }

    def generate_random_network(self, codename: str, num_public: int = 5, num_private: int = 3,
                                codename_in_public: bool = True):
        if num_public <= 0:
            num_public = 1
        total = max(1, num_public + max(0, num_private))

        # Spread across 192.168.X.Y subnets — each /24 holds 253 usable hosts
        usable_per_subnet = 253
        subnets_needed    = max(1, (total + usable_per_subnet - 1) // usable_per_subnet)
        all_ips: list[str] = []
        for third in range(subnets_needed):
            for fourth in range(2, 255):
                all_ips.append(f"192.168.{third}.{fourth}")
                if len(all_ips) >= total * 4:
                    break
            if len(all_ips) >= total * 4:
                break

        chosen_ips  = random.sample(all_ips, min(total, len(all_ips)))
        public_ips  = chosen_ips[:num_public]
        private_ips = chosen_ips[num_public:]

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
        codename_ip = None
        if bool(codename):
            if codename_in_public:
                codename_ip = random.choice(public_ips)
            else:
                codename_ip = random.choice(private_ips)

        for ip in public_ips:
            last      = ip.split(".")[-1]
            host_type = random.choice(host_types)
            os_choice = random.choice(os_choices)
            is_target = (ip == codename_ip and codename_in_public)
            prefix    = {"web": "web", "db": "db", "generic": "host"}[host_type]
            name      = f"{prefix}-{last}"

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
                "kernel":       rand_kernel(),
                "ssh_version":  f"SSH-2.0-OpenSSH_{random.choice(['8.9p1','9.2p1','9.6p1','8.4p1'])}",
            }

        for ip in private_ips:
            last        = ip.split(".")[-1]
            host_type   = random.choice(host_types)
            os_choice   = random.choice(os_choices)
            is_target   = (ip == codename_ip and not codename_in_public)
            passwd      = random_password()
            auth_user   = random.choice(["admin", "root", "dbadmin", "administrator", "deploy"])
            name        = f"priv-{last}"

            home_message = (
                "You are on the correct server.\n\n"
                "The codename is hidden somewhere on this host.\n"
                "Explore the filesystem carefully\n"
                if is_target
                else "This is not the correct server. Try another host."
            )

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
                "shell_hint":   "Check the home directory for clues.",
                "is_target":    is_target,
                "home_message": home_message,
                "codename":     codename if is_target else "",
                "uptime_days":  random.randint(1, 400),
                "kernel":       rand_kernel(),
                "ssh_version":  f"SSH-2.0-OpenSSH_{random.choice(['8.9p1','9.2p1','9.6p1','8.4p1'])}",
            }

        self.network = network
        self.rebuild_network_pwd()

    def rebuild_network_pwd(self):
        etc = self.root.children["etc"]

        protected_hosts = []
        for ip, host in self.network.items():
            if host.get("password"):
                protected_hosts.append(f"IP:{ip} - PWD:{host['password']}")

        # overwrite existing node if it exists
        etc.children["network_pwd"] = Node(
            "network_pwd",
            etc,
            False,
            "\n".join(protected_hosts) + "\n",
            owner="root",
            permissions="rw-------"
        )