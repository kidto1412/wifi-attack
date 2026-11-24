# modern_breach.py — modern WiFi / SOHO router breach toolkit (no brute force)

Installs on the box (Termux on Android or Linux):
  pkg install python aircrack-ng hcxtools hostapd dnsmasq airbase-ng bettercap nmap termux-tools
  # root required for monitor mode, rogue AP, PMKID, KRACK, fragmentation, DNS rebinding port 53

Run:
  python3 modern_breach.py <subcommand> [options]

Menu mode (no args):
  python3 modern_breach.py   -> interactive numbered menu over all vectors

Vectors (sophisticated, modern, no wordlists):

  recon           Passive/active AP + LAN fingerprinting (airodump-ng, wash, nmap)
  pmkid           PMKID capture via RSN IE replay — no handshake, no client needed
  krack           KRACK key-reinstallation detection + frame replay (WPA2, no 802.11w)
  fragattacks     Fragmentation / aggregation flaws (2021) — plaintext injection, NAT bypass
  wpa3            WPA3 / Dragonblood downgrade detection — force transition mode to WPA2
  karma           KARMA rogue AP — answers probe requests for probed SSIDs, forces association
  evil-twin       Rogue AP + captive portal credential phish
  dns-rebind      DNS rebinding payload + flip DNS server — SOP bypass to reach router UI from browser
  router-inject   SOHO router command-injection probe on diagnostic CGI endpoints
  csrf-dns        CSRF payload that silently changes router DNS via cross-site form submission
  upnp            UPnP / TR-064 SOAP manipulation — port mapping, DNS, remote management

Examples:
  python3 modern_breach.py recon -i wlan0 --net 192.168.1.0/24
  python3 modern_breach.py pmkid -i wlan0mon
  python3 modern_breach.py krack -i wlan0mon --bssid AA:BB:CC:DD:EE:FF --client AA:BB:CC:DD:EE:00
  python3 modern_breach.py fragattacks -i wlan0mon --bssid AA:BB:CC:DD:EE:FF
  python3 modern_breach.py wpa3 -i wlan0 --bssid AA:BB:CC:DD:EE:FF
  python3 modern_breach.py karma -i wlan0 --ssid "Free_WiFi"
  python3 modern_breach.py dns-rebind --target 192.168.1.1 --domain rebind.local
  python3 modern_breach.py router-inject --target 192.168.1.1 --port 80
  python3 modern_breach.py csrf-dns --target 192.168.1.1 --dns1 8.8.8.8 --dns2 8.8.4.4
  python3 modern_breach.py upnp --target 192.168.1.1 --port 49152

Outputs land in modern_work/captures/, modern_work/loot/, modern_work/payloads/.

Defeated by: 802.11w / management frame protection, WPA3-only (no transition mode), SameSite cookies,
CSRF tokens, UPnP disabled, router admin re-auth, network isolation, patched SOHO firmware.

Root required for: pmkid, krack, fragattacks, karma, evil-twin, dns-rebind port 53.
