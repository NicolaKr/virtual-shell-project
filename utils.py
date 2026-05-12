"""utils.py – shared utilities for the virtual shell project.

Contains:
  - random_password()        — generate a random password string
  - encrypt_codename()       — obfuscate a plain codename for embedding in notebooks
  - decrypt_codename()       — reverse of encrypt_codename
"""

import base64
import random
import string
import datetime

# XOR key used for codename obfuscation (must match in cli.py)
_KEY = 120


def random_password(length: int = 8) -> str:
    """Return a random alphanumeric password of the given length."""
    return "".join(random.choice(string.ascii_letters + string.digits)
                   for _ in range(length))


def rand_ip():
    return f"192.168.{random.randint(0,2)}.{random.randint(1,254)}"


def rand_data(days_back=365):
    d = datetime.datetime.now() - datetime.timedelta(days=random.randint(0, days_back))
    return d.strftime("%Y-%m-%d")


def rand_config(service):
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


def rand_script(name):
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


def rand_kernel():
    patch = random.randint(0, 30)
    minor = random.choice([15, 16, 17, 18, 19])
    major = random.choice([5, 6])
    return (f"{major}.{minor}.{patch}-{random.randint(1,9)}-generic "
            f"#{random.randint(30,99)}-Ubuntu SMP x86_64")


def rand_log_lines(service:str="syslog", count=8):
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
            u=random.choice(users), ip=rand_ip(),
            p=random.randint(40000, 65000), date=rand_data(30),
            pid=random.randint(1000, 9999),
        )
        dt = datetime.datetime.now() - datetime.timedelta(
            hours=random.randint(0, 72), minutes=random.randint(0, 59))
        ts = dt.strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} {service}[{random.randint(100,9999)}]: {line}")
    return "\n".join(sorted(lines))


def rand_crontab(user: str) -> str:
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


def encrypt_codename(plain: str) -> str:
    """Encrypt a plain codename → opaque string safe to embed in a notebook cell.

    Flow:  plain  ──b64encode──▶  bytes  ──XOR──▶  bytes  ──b64encode──▶  str
    The outer b64 makes the result printable / copy-pasteable.
    """
    xored = bytes(b ^ _KEY for b in base64.b64encode(plain.encode()))
    return base64.b64encode(xored).decode()


def decrypt_codename(token: str) -> str:
    """Reverse of encrypt_codename.  Raises ValueError on a bad token."""
    try:
        xored = base64.b64decode(token.encode())
        inner = bytes(b ^ _KEY for b in xored)
        return base64.b64decode(inner).decode()
    except Exception as exc:
        raise ValueError(f"Invalid encrypted codename token: {token!r}") from exc