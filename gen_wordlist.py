#!/usr/bin/env python3
# gen_wordlist.py — generates combined English + Indonesian Wi-Fi password wordlist
# output: wordlist_en_id.txt
# usage: python3 gen_wordlist.py [--output FILE] [--rules FILE] [--target-ssid SSID]

import argparse
import re
from pathlib import Path
from itertools import product

DEFAULT_OUTPUT = Path(__file__).parent / "wordlist_en_id.txt"

# ─── ENGLISH BASE WORDS ───────────────────────────────────────────────────────
english_words = [
    # common passwords
    "password", "password1", "password123", "passw0rd", "pa$$word",
    "qwerty", "qwerty123", "qwertyuiop", "123456", "1234567", "12345678",
    "123456789", "1234567890", "111111", "000000", "666666", "888888",
    "admin", "admin123", "administrator", "root", "root123", "toor",
    "letmein", "welcome", "welcome1", "iloveyou", "monkey", "dragon",
    "master", "login", "pass", "test", "test123", "demo", "guest",
    "access", "access123", "secret", "default", "changeme",
    # names
    "michael", "jessica", "ashley", "jennifer", "joshua", "andrew",
    "daniel", "matthew", "james", "robert", "john", "david", "william",
    "richard", "charles", "joseph", "thomas", "christopher", "kevin",
    "brian", "george", "edward", "mark", "donald", "paul", "steven",
    "emily", "hannah", "madison", "emma", "olivia", "sophia", "isabella",
    "mia", "abigail", "elizabeth", "samantha", "lauren", "sarah",
    # common wifi names / routers
    "wifi", "wireless", "network", "internet", "router", "modem",
    "home", "house", "office", "mynetwork", "mywifi", "myhome",
    # seasons/months
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "spring", "summer", "autumn", "winter",
    # common phrases
    "sunshine", "football", "baseball", "soccer", "basketball",
    "superman", "batman", "spiderman", "ironman", "starwars",
    "matrix", "shadow", "hunter", "killer", "ranger", "warrior",
    "princess", "angel", "devil", "fire", "thunder", "storm",
    "falcon", "eagle", "tiger", "lion", "wolf", "cobra", "viper",
    "ninja", "samurai", "pirate", "phantom", "ghost", "stealth",
    # router brands / defaults
    "linksys", "netgear", "tp-link", "tplink", "dlink", "asus",
    "belkin", "cisco", "ubiquiti", "unifi", "mikrotik", "huawei",
    "zte", "fiberhome", "alcatel", "technicolor", "arris", "motorola",
]

# ─── INDONESIAN BASE WORDS ────────────────────────────────────────────────────
indonesian_words = [
    # common Indonesian passwords / phrases
    "indonesia", "indonesia1", "indonesian",
    # major cities
    "jakarta", "surabaya", "bandung", "medan", "semarang", "makassar",
    "bali", "yogyakarta", "jogja", "malang", "depok", "tangerang",
    "bogor", "bekasi", "batam", "pekanbaru", "palembang", "bandar lampung",
    "denpasar", "solo", "semarang", "makassar", "manado", "bontang",
    "balikpapan", "samarinda", "pontianak", "banjarmasin", "padang", "pekanbaru",
    # numbers in Indonesian
    "satu", "dua", "tiga", "empat", "lima", "enam", "tujuh", "delapan",
    "sembilan", "sepuluh", "seratus", "seribu", "sejuta",
    # common words
    "rumah", "rumahku", "keluarga", "keluargaku", "rumahkita",
    "cinta", "sayang", "kasih", "cintaku", "sayangku", "kasihku",
    "selamat", "sukses", "bahagia", "merdeka", "semangat", "jaya",
    # islamic phrases (very common in ID wifi passwords)
    "allah", "bismillah", "alhamdulillah", "insyaallah", "subhanallah",
    "astaghfirullah", "mashallah", "laillahaillallah", "muhammad", "rasulullah",
    "assalamualaikum", "waalaikumsalam", "amin", "amien",
    # common Indonesian names
    "budi", "andi", "joko", "sari", "dewi", "sri", "rina", "rini",
    "agus", "bambang", "doni", "eko", "fajar", "gunawan", "hendra",
    "irwan", "jaya", "karya", "luki", "marco", "nova", "okta", "pandu",
    "rahmat", "sandi", "taufik", "umar", "vino", "wahyu", "xander",
    "yoga", "zaki", "dian", "fitri", "gita", "hana", "indah", "julia",
    "kartika", "laras", "maya", "nadia", "putri", "reza", "sinta",
    "putra", "adi", "bayu", "candra", "dimas", "erick", "febri",
    # common Indonesian wifi passwords
    "wifi123", "wifikita", "wifindonesia", "hotspot", "hotspot123",
    "adminadmin", "admin1234", "1234admin", "admin12345",
    "rahasia", "rahasia123", "password", "sandi", "sandikata", "kata_sandi",
    "jaringan", "internet123", "netsecure", "wlan", "wlan123",
    # telco / ISP defaults (very common in Indonesia)
    "telkom", "indihome", "indihome123", "firstmedia", "biznet",
    "speedy", "speedy123", "telkomsel", "xl123", "indosat", "indosat123",
    "byu", "byu123", "cbn", "cbn123", "myrepublic", "oxygen", "oxygen123",
    "three", "three123", "tri", "tri123", "smartfren", "smartfren123",
    "axis", "axis123", "h3i", "h3i123", "boltasel", "boltasel123",
    # popular brands / e-commerce
    "indomaret", "alfamart", "tokopedia", "bukalapak", "gojek", "grab",
    "shopee", "shopee123", "lazada", "blibli", "bukalapak123",
    # slang / gen-z Indonesian
    "mantap", "mantul", "gokil", "anjay", "wkwk", "wkwkwk",
    "ngakak", "baper", "bucin", "sultan", "gabut", "gaskeun",
    "santuy", "kepo", "mager", "otw", "japri", "selebgram",
    "anjir", "asw", "asuw", "bgst", "bgsd", "tolol", "bodoh",
    # national / patriotic
    "17agustus", "1945", "pancasila", "bhinneka", "merahputih",
    "garuda", "nkri", "nkrihargamati", "bhinnekatunggalika",
    "proklamasi", "kemerdekaan", "tanahairku", "indonesiamaju",
    # keyboard patterns
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "1qazxsw2",
]

# ─── YEAR SUFFIXES ────────────────────────────────────────────────────────────
years = [str(y) for y in range(1970, 2027)]
short_years = [str(y)[2:] for y in range(1970, 2027)]
common_nums = [
    "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "0", "00", "000", "0000", "007", "008", "009",
    "1!", "123!", "!", "@", "#", "$", "%", "&", "*",
    "2024", "2023", "2022", "2021", "2020", "2019", "2018", "2017", "2016", "2015",
    "24", "23", "22", "21", "20", "19", "18", "17", "16", "15",
]

# ─── LEET SUBSTITUTIONS ───────────────────────────────────────────────────────
leet_map = str.maketrans("aeiostAEIOST", "43!05743!057")
leet_map_extended = str.maketrans("aeiostbgAEIOSTBG", "43!0578943!05789")


def leet(word: str) -> str:
    return word.translate(leet_map)


def leet_extended(word: str) -> str:
    return word.translate(leet_map_extended)


def capitalize_variants(word: str) -> list[str]:
    return [
        word,
        word.capitalize(),
        word.upper(),
        word[0].upper() + word[1:] if len(word) > 1 else word,
    ]


def apply_rules(word: str, rules: list[str]) -> list[str]:
    """Apply hashcat-style rules to a word."""
    results = [word]
    for rule in rules:
        if rule == ":":
            results.append(word)  # noop
        elif rule.startswith("c"):
            results.append(word.capitalize())
        elif rule.startswith("u"):
            results.append(word.upper())
        elif rule.startswith("l"):
            results.append(word.lower())
        elif rule.startswith("r"):
            results.append(word[::-1])
        elif rule.startswith("t"):
            results.append(word.capitalize() if word.islower() else word.lower())
        elif rule.startswith("["):
            results.append(word + rule[1:])
        elif rule.startswith("]"):
            results.append(rule[1:] + word)
        elif rule.startswith("s"):
            # sXY = replace X with Y
            if len(rule) >= 3:
                x, y = rule[1], rule[2]
                results.append(word.replace(x, y))
        elif rule.startswith("S"):
            # SXY = replace all X with Y
            if len(rule) >= 3:
                x, y = rule[1], rule[2]
                results.append(word.replace(x, y))
        elif rule.startswith("i"):
            # iNX = insert X at position N
            if len(rule) >= 3:
                try:
                    pos = int(rule[1])
                    char = rule[2]
                    if pos <= len(word):
                        results.append(word[:pos] + char + word[pos:])
                except ValueError:
                    pass
        elif rule.startswith("d"):
            # dN = delete character at position N
            if len(rule) >= 2:
                try:
                    pos = int(rule[1])
                    if pos < len(word):
                        results.append(word[:pos] + word[pos+1:])
                except ValueError:
                    pass
    return results


# Default hashcat-style rules for Wi-Fi passwords
DEFAULT_RULES = [
    ":", "c", "u", "l", "r", "t",
    "s@a", "s3e", "s!i", "s0o", "s5s", "s7t",
    "S@a", "S3e", "S!i", "S0o", "S5s", "S7t",
    "[1", "[12", "[123", "[1234", "[!@", "[#$",
    "]1", "]12", "]123", "]!",
    "i0!", "i0@", "i0#", "i0$",
]


def generate_wordlist(target_ssid: str = None, custom_words: list[str] = None, rules: list[str] = None) -> list[str]:
    words = set()
    all_base = english_words + indonesian_words

    if custom_words:
        all_base.extend(custom_words)

    if target_ssid:
        # Add SSID-based mutations
        ssid_clean = re.sub(r'[^\w]', '', target_ssid.lower())
        all_base.append(ssid_clean)
        all_base.append(ssid_clean + "123")
        all_base.append(ssid_clean + "admin")
        all_base.append("admin" + ssid_clean)

    if rules is None:
        rules = DEFAULT_RULES

    for w in all_base:
        w = w.strip().lower()
        if not w:
            continue
        for variant in capitalize_variants(w):
            words.add(variant)
            words.add(leet(variant))
            words.add(leet_extended(variant))

            # Apply rules
            for ruled in apply_rules(variant, rules):
                words.add(ruled)

            # + common number suffixes
            for num in common_nums:
                words.add(variant + num)
                words.add(num + variant)
                words.add(leet(variant) + num)
                words.add(num + leet(variant))

            # + year suffixes (selective — only on base + capitalize)
            for y in years[-20:]:  # last 20 years
                words.add(variant + y)
            for sy in short_years[-15:]:
                words.add(variant + sy)

    # pure number sequences
    for combo in [
        "0000", "1111", "1234", "4321", "0987", "9876",
        "12345", "54321", "123456", "654321",
        "1234567", "12345678", "123456789", "987654321",
        "111111", "222222", "333333", "444444", "555555",
        "666666", "777777", "888888", "999999", "000000",
    ]:
        words.add(combo)

    # common Indonesian + English combos
    combo_pairs = [
        ("wifi", "rumah"), ("wifi", "kantor"), ("wifi", "indihome"),
        ("cinta", "selamanya"), ("admin", "jakarta"), ("admin", "indihome"),
        ("indo", "maju"), ("garuda", "indonesia"), ("merah", "putih"),
        ("home", "sweet"), ("my", "wifi"), ("the", "best"), ("love", "you"),
        ("telkom", "indihome"), ("first", "media"), ("biznet", "home"),
        ("speedy", "telkom"), ("indosat", "ooredoo"), ("xl", "axiata"),
        ("smart", "fren"), ("three", "indonesia"), ("byu", "fiber"),
        ("rumah", "ku"), ("keluarga", "bahagia"), ("bismillah", "hijrah"),
    ]
    for a, b in combo_pairs:
        words.add(a + b)
        words.add(a + "_" + b)
        words.add(a + b + "123")
        words.add(a.capitalize() + b.capitalize())
        words.add(a + b + "2024")
        words.add(a + b + "2023")

    # Keyboard patterns (Indonesian keyboard layout same as US)
    kb_patterns = [
        "qwerty", "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1qaz2wsx", "1qazxsw2", "zaq1xsw2", "qazwsxedc",
        "123qwe", "123qweasd", "qweasdzxc", "asdzxc123",
    ]
    for p in kb_patterns:
        words.add(p)
        words.add(p + "123")
        words.add(p.capitalize())

    # Indonesian phone number patterns (common in passwords)
    phone_prefixes = ["081", "082", "083", "085", "087", "088", "089",
                      "6281", "6282", "6283", "6285", "6287", "6288", "6289"]
    for prefix in phone_prefixes:
        for suffix in ["1234", "12345", "123456", "0000", "1111", "1234567"]:
            words.add(prefix + suffix)

    return sorted(words)


def load_custom_words(filepath: str) -> list[str]:
    words = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    return words


def load_rules(filepath: str) -> list[str]:
    rules = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(line)
    return rules


def main():
    parser = argparse.ArgumentParser(description="Generate EN/ID Wi-Fi password wordlist")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="Output file path")
    parser.add_argument("--target-ssid", help="Target SSID for targeted mutations")
    parser.add_argument("--custom-words", help="File with custom base words (one per line)")
    parser.add_argument("--rules", help="File with hashcat-style rules (one per line)")
    parser.add_argument("--no-default-rules", action="store_true", help="Don't apply default rules")
    args = parser.parse_args()

    custom_words = load_custom_words(args.custom_words) if args.custom_words else None
    rules = None if args.no_default_rules else (load_rules(args.rules) if args.rules else DEFAULT_RULES)

    print("[*] generating combined EN + ID wordlist...")
    if args.target_ssid:
        print(f"[*] targeting SSID: {args.target_ssid}")
    if custom_words:
        print(f"[*] loaded {len(custom_words)} custom words")
    if rules:
        print(f"[*] loaded {len(rules)} rules")

    words = generate_wordlist(target_ssid=args.target_ssid, custom_words=custom_words, rules=rules)

    with open(args.output, "w") as f:
        f.write("\n".join(words) + "\n")

    print(f"[+] done → {args.output}")
    print(f"[+] total entries: {len(words):,}")


if __name__ == "__main__":
    main()