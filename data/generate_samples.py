"""Sample data generator — creates PCAP and log files with embedded attack patterns for demonstration."""

import os
import random
from datetime import datetime, timedelta

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Ether, wrpcap, Raw

random.seed(42)


def generate_pcap(filepath: str):
    base_time = datetime(2026, 3, 15, 10, 0, 0)
    base_epoch = base_time.timestamp()
    packets = []

    # --- Normal traffic (~300 packets, spread over 5 minutes) ---

    normal_domains = [
        b"example.com", b"google.com", b"github.com", b"cdn.jsdelivr.net",
        b"api.internal.local", b"mail.company.org",
    ]

    for i in range(300):
        offset = random.uniform(0, 300)
        src_host = random.randint(10, 50)
        roll = random.random()

        if roll < 0.4:
            # HTTP / HTTPS traffic
            dport = random.choice([80, 443])
            pkt = IP(src=f"192.168.1.{src_host}", dst="10.0.0.1") / TCP(
                sport=random.randint(49152, 65535),
                dport=dport,
                flags="SA",
            )
        elif roll < 0.7:
            # DNS queries
            domain = random.choice(normal_domains)
            pkt = (
                IP(src=f"192.168.1.{src_host}", dst="10.0.0.53")
                / UDP(sport=random.randint(49152, 65535), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=domain))
            )
        else:
            # HTTPS to external
            ext_host = random.randint(1, 254)
            pkt = IP(src=f"192.168.1.{src_host}", dst=f"203.0.113.{ext_host}") / TCP(
                sport=random.randint(49152, 65535),
                dport=443,
                flags="SA",
            )

        pkt.time = base_epoch + offset
        packets.append(pkt)

    # --- Port scan pattern (~80 packets, within 30 seconds starting at +60s) ---

    for port in range(1, 81):
        offset = 60 + (port - 1) * (30.0 / 80)
        pkt = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(
            sport=random.randint(49152, 65535),
            dport=port,
            flags="S",
        )
        pkt.time = base_epoch + offset
        packets.append(pkt)

    # --- SYN flood pattern (~80 packets, within 10 seconds starting at +180s) ---

    for i in range(80):
        offset = 180 + random.uniform(0, 10)
        src_host = random.randint(1, 20)
        pkt = IP(src=f"172.16.0.{src_host}", dst="10.0.0.1") / TCP(
            sport=random.randint(49152, 65535),
            dport=80,
            flags="S",
        )
        pkt.time = base_epoch + offset
        packets.append(pkt)

    # --- Beaconing pattern (~20 packets, every 60 seconds starting at +30s) ---

    for i in range(20):
        offset = 30 + i * 60
        pkt = (
            IP(src="192.168.1.50", dst="198.51.100.1")
            / TCP(sport=random.randint(49152, 65535), dport=8888, flags="S")
            / Raw(load=b"beacon")
        )
        pkt.time = base_epoch + offset
        packets.append(pkt)

    # --- Data exfiltration (~5 packets at +240s) ---

    for i in range(5):
        offset = 240 + i * 0.5
        pkt = (
            IP(src="192.168.1.30", dst="203.0.113.99")
            / TCP(sport=random.randint(49152, 65535), dport=443, flags="PA")
            / Raw(load=b"x" * random.randint(1400, 1500))
        )
        pkt.time = base_epoch + offset
        packets.append(pkt)

    packets.sort(key=lambda p: p.time)
    wrpcap(filepath, packets)


def generate_syslog(filepath: str):
    base_time = datetime(2026, 3, 15, 10, 0, 0)
    lines = []

    def fmt_ts(dt):
        return dt.strftime("Mar 15 %H:%M:%S")

    # --- Normal entries (~150 lines) ---

    services_normal = [
        ("firewall", "CRON[{pid}]: (root) CMD (/usr/bin/periodic daily)"),
        ("firewall", "systemd[1]: Started Session {session} of user admin."),
        ("webserver", "kernel: [{uptime}] eth0: link up at 1000 Mbps"),
        ("gateway", "sshd[{pid}]: Accepted publickey for admin from 192.168.1.10 port {port} ssh2"),
        ("firewall", "systemd[1]: Starting Daily apt download activities..."),
        ("webserver", "kernel: [{uptime}] TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies."),
        ("gateway", "dhclient[1234]: DHCPACK of 192.168.1.25 from 192.168.1.1"),
        ("firewall", "systemd[1]: Finished Daily man-db regeneration."),
    ]

    for i in range(150):
        offset = timedelta(seconds=random.uniform(0, 300))
        ts = fmt_ts(base_time + offset)
        tmpl_hostname, tmpl_msg = random.choice(services_normal)
        msg = tmpl_msg.format(
            pid=random.randint(1000, 30000),
            session=random.randint(1, 500),
            uptime=f"{random.randint(400000, 430000)}.{random.randint(100, 999)}",
            port=random.randint(49152, 65535),
        )
        lines.append((base_time + offset, f"{ts} {tmpl_hostname} {msg}"))

    # --- SSH brute force (~15 lines within 45 seconds starting at 10:02:00) ---

    brute_start = base_time + timedelta(minutes=2)
    base_port = 50000
    for i in range(15):
        offset = timedelta(seconds=i * 3)
        ts = fmt_ts(brute_start + offset)
        port = base_port + i
        lines.append((
            brute_start + offset,
            f"{ts} gateway sshd[9901]: Failed password for root from 10.99.88.77 port {port} ssh2",
        ))

    # Successful login after brute force
    success_time = brute_start + timedelta(seconds=46)
    ts = fmt_ts(success_time)
    lines.append((
        success_time,
        f"{ts} gateway sshd[9901]: Accepted password for root from 10.99.88.77 port 55555 ssh2",
    ))

    # --- Error entries (~20 lines scattered) ---

    error_templates = [
        ("webserver", "kernel: [{uptime}] Out of memory: Killed process 4521 (java)"),
        ("gateway", "sshd[7721]: Failed password for invalid user test from 203.0.113.50 port 22"),
        ("firewall", "kernel: [{uptime}] possible SYN flooding on port 443. Sending cookies."),
        ("webserver", "kernel: [{uptime}] EXT4-fs warning: mounting unchecked fs"),
        ("gateway", "sshd[8100]: Invalid user admin from 203.0.113.50 port 22"),
        ("firewall", "systemd[1]: Failed to start Apache HTTP Server."),
        ("webserver", "kernel: [{uptime}] nf_conntrack: table full, dropping packet"),
        ("gateway", "sshd[8200]: Connection closed by 203.0.113.50 port 22 [preauth]"),
    ]

    for i in range(20):
        offset = timedelta(seconds=random.uniform(0, 300))
        ts = fmt_ts(base_time + offset)
        tmpl_hostname, tmpl_msg = random.choice(error_templates)
        msg = tmpl_msg.format(
            uptime=f"{random.randint(423000, 423500)}.{random.randint(100, 999)}",
        )
        lines.append((base_time + offset, f"{ts} {tmpl_hostname} {msg}"))

    lines.sort(key=lambda x: x[0])

    with open(filepath, "w") as f:
        for _, line in lines:
            f.write(line + "\n")


def generate_apache(filepath: str):
    base_time = datetime(2026, 3, 15, 10, 0, 0)
    lines = []

    normal_paths = [
        "/", "/about", "/products", "/api/v1/data",
        "/assets/style.css", "/images/logo.png",
        "/contact", "/faq", "/api/v1/users", "/docs",
    ]
    normal_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]
    referers = ["-", "https://example.com/", "https://www.google.com/", "https://github.com/"]

    def fmt_ts(dt):
        return dt.strftime("15/Mar/2026:%H:%M:%S +0100")

    # --- Normal traffic (~220 lines) ---

    for i in range(220):
        offset = timedelta(seconds=random.uniform(0, 300))
        ts = fmt_ts(base_time + offset)
        ip = f"192.168.1.{random.randint(10, 50)}"
        path = random.choice(normal_paths)
        status = random.choice([200, 200, 200, 200, 301, 304])
        size = random.randint(200, 15000)
        agent = random.choice(normal_agents)
        referer = random.choice(referers)
        line = f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {size} "{referer}" "{agent}"'
        lines.append((base_time + offset, line))

    # --- Directory traversal attempts (~15 lines) ---

    traversal_paths = [
        "/../../etc/passwd",
        "/..%2f..%2fetc/shadow",
        "/admin/../../../etc/hosts",
        "/....//....//etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/cgi-bin/../../etc/passwd",
        "/static/../../etc/shadow",
        "/admin/../../../etc/group",
        "/..%252f..%252f..%252fetc/passwd",
        "/../../../var/log/auth.log",
        "/..;/..;/etc/passwd",
        "/admin/..%2f..%2f..%2fetc/hosts",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/....\\....\\etc\\passwd",
        "/..%255c..%255c..%255cetc/passwd",
    ]

    for i, path in enumerate(traversal_paths):
        offset = timedelta(seconds=random.uniform(60, 120))
        ts = fmt_ts(base_time + offset)
        agent = random.choice(normal_agents)
        line = f'10.99.88.77 - - [{ts}] "GET {path} HTTP/1.1" 403 287 "-" "{agent}"'
        lines.append((base_time + offset, line))

    # --- 404 scanning (~30 lines) ---

    scan_paths = [
        "/wp-admin", "/wp-login.php", "/phpmyadmin", "/pma",
        "/.env", "/config.php", "/admin", "/backup.sql",
        "/.git/config", "/server-status", "/.htaccess",
        "/wp-content/uploads/", "/xmlrpc.php", "/administrator",
        "/solr/admin", "/console", "/.svn/entries", "/debug",
        "/api/config", "/.DS_Store", "/web.config",
        "/actuator/health", "/graphql", "/swagger.json",
        "/_config.yml", "/robots.txt.bak", "/sitemap.xml.gz",
        "/phpinfo.php", "/info.php", "/test.php", "/dump.sql",
    ]

    scan_agent = "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
    for i, path in enumerate(scan_paths):
        offset = timedelta(seconds=random.uniform(30, 90))
        ts = fmt_ts(base_time + offset)
        line = f'203.0.113.50 - - [{ts}] "GET {path} HTTP/1.1" 404 196 "-" "{scan_agent}"'
        lines.append((base_time + offset, line))

    # --- HTTP flood (~40 lines within 5 seconds) ---

    flood_start = base_time + timedelta(seconds=200)
    for i in range(40):
        offset = timedelta(seconds=random.uniform(0, 5))
        ts = fmt_ts(flood_start + offset)
        ip = f"172.16.0.{random.randint(1, 15)}"
        agent = random.choice(normal_agents)
        size = random.randint(100, 300)
        line = f'{ip} - - [{ts}] "POST /api/login HTTP/1.1" 401 {size} "-" "{agent}"'
        lines.append((flood_start + offset, line))

    lines.sort(key=lambda x: x[0])

    with open(filepath, "w") as f:
        for _, line in lines:
            f.write(line + "\n")


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    generate_pcap(os.path.join(script_dir, "sample_capture.pcap"))
    generate_syslog(os.path.join(script_dir, "sample_syslog.log"))
    generate_apache(os.path.join(script_dir, "sample_apache.log"))
    print("Sample data generated successfully.")
