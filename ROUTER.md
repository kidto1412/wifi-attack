# router_breach.py — modern WiFi / SOHO router offensive toolkit

Installs on the attacking box (Termux on Android or Linux):
  pkg install python aircrack-ng hcxtools reaver wash nmap termux-tools
  # root required for monitor mode, raw sockets, PMKID, handshake

Run:
  python3 router_breach.py <subcommand> [options]

Vectors (not brute-force limited):
  recon        LAN + WiFi recon (nmap host discovery, iw dev, gateway)
  pmkid        PMKID capture against WPA-PSK — no handshake, no client needed
  handshake    WPA 4-way handshake capture (with deauth to force reauth)
  wps          WPS Pixie Dust / offline PIN attack (wash + reaver)
  deauth       deauthentication / disassociation flood
  router       router admin breach — default creds + credential spray + injection probes
  post         post-exploitation — config backup download, DNS hijack, remote admin

Examples:
  python3 router_breach.py recon --net 192.168.1.0/24
  python3 router_breach.py pmkid -i wlan0mon
  python3 router_breach.py handshake -i wlan0mon --bssid AA:BB:CC:DD:EE:FF --channel 6
  python3 router_breach.py wps -i wlan0mon --bssid AA:BB:CC:DD:EE:FF
  python3 router_breach.py deauth -i wlan0mon --bssid AA:BB:CC:DD:EE:FF
  python3 router_breach.py router --target 192.168.1.1 --port 80
  python3 router_breach.py post --target 192.168.1.1 --creds admin:admin

Outputs land in router_work/captures/ and router_work/loot/.

Root is required for PMKID, handshake, deauth, and monitor-mode subcommands.
