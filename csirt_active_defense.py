#!/usr/bin/env python3
"""
py-simpledefense - Hybrid Apache WAF & Real-Time Telegram Alert Daemon
Menjaga server Linux dengan cara simpel tanpa membebani CPU dan memori.

Arsitektur Hybrid:
1. Apache WAF (configs/apache-global-waf.conf) menolak percobaan eksploitasi
   secara instan di level web server dengan HTTP 403 Forbidden sebelum request
   menyentuh PHP-FPM, aplikasi, atau database.
2. Daemon Python ini memantau access log secara real-time (mendukung rotasi log
   otomatis), mendeteksi pola serangan siber, mengirimkan peringatan terformat
   ke Telegram, serta memiliki opsi auto-ban IP berulang via iptables.

Lisensi: MIT License - Copyright (c) 2026 Muhammad Takdir
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


def load_dotenv_file(env_path: Path) -> None:
    """Memuat variabel dari berkas .env menggunakan pustaka standar Python."""
    if not env_path.is_file():
        return
    try:
        with env_path.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError as exc:
        print(f"[WARN] Gagal membaca {env_path}: {exc}", file=sys.stderr)


# Urutan pencarian berkas konfigurasi .env
for candidate in (
    Path(os.environ.get("SIMPLEDEFENSE_ENV", "")),
    Path(__file__).resolve().parent / ".env",
    Path("/etc/py-simpledefense/config.env"),
):
    if str(candidate) and candidate.is_file():
        load_dotenv_file(candidate)
        break


def parse_csv_env(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def expand_log_glob_patterns(patterns: list[str]) -> list[str]:
    """Mendukung wildcard / globbing pada daftar log (misal: /var/log/apache2/*access*.log)."""
    import glob
    expanded: list[str] = []
    for pat in patterns:
        if any(char in pat for char in ("*", "?", "[")):
            matched = glob.glob(pat)
            if matched:
                expanded.extend(sorted(matched))
            else:
                # Bila belum ada file yang cocok (misal log belum dibuat), tetap simpan polanya
                expanded.append(pat)
        else:
            expanded.append(pat)
    # Deduplikasi tanpa merusak urutan
    seen = set()
    result = []
    for item in expanded:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


SERVER_LABEL = os.environ.get("SERVER_LABEL", "server.example.com")
SERVER_PUBLIC_IP = os.environ.get("SERVER_PUBLIC_IP", "-")
TIMEZONE_LABEL = os.environ.get("TIMEZONE_LABEL", "LOCAL")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_IDS = parse_csv_env("TELEGRAM_CHAT_IDS", "")

_RAW_LOG_FILES = parse_csv_env(
    "LOG_FILES",
    "/var/log/apache2/*access*.log,/var/log/nginx/*access*.log,/var/log/apache2/access.log",
)
LOG_FILES = expand_log_glob_patterns(_RAW_LOG_FILES)
WHITELIST_IPS = set(parse_csv_env("WHITELIST_IPS", "127.0.0.1,::1"))

ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "300"))
AUTO_BAN_ENABLED = os.environ.get("AUTO_BAN_ENABLED", "false").lower() in ("1", "true", "yes")
AUTO_BAN_THRESHOLD = int(os.environ.get("AUTO_BAN_THRESHOLD", "10"))
AUTO_BAN_WINDOW_SECONDS = int(os.environ.get("AUTO_BAN_WINDOW_SECONDS", "120"))

IP_VALID_RE = re.compile(r"^[0-9a-fA-F:.]{3,45}$")

ATTACK_PATTERNS = [
    (
        re.compile(
            r"(?i)(union\s+select|select\s+.*\s+from|into\s+outfile|into\s+dumpfile|"
            r"benchmark\s*\(|waitfor\s+delay|sleep\s*\(\d+\)|load_file\s*\()"
        ),
        "SQL Injection Attempt",
    ),
    (
        re.compile(
            r"(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|win\.ini)"
        ),
        "Directory Traversal / LFI",
    ),
    (
        re.compile(
            r"(?i)(\.env|\.git/|\.svn/|wp-config\.php|composer\.lock|composer\.json|"
            r"phpinfo\.php|info\.php|database\.php|\.bak|\.sql)"
        ),
        "Sensitive File Probing",
    ),
    (
        re.compile(
            r"(?i)(eval\s*\(|base64_decode\s*\(|passthru\s*\(|shell_exec\s*\(|"
            r"system\s*\(|assert\s*\(|php://input|data://text)"
        ),
        "PHP Code Injection / Web Shell",
    ),
    (
        re.compile(r"(?i)(/phpmyadmin/|/pma/|/adminer\.php|/mysql/|/sql/|xmlrpc\.php)"),
        "Unauthorized Admin / DB Probing",
    ),
    (
        re.compile(r"(?i)(<script|javascript:|alert\s*\(|onerror=|onload=|<svg)"),
        "Cross-Site Scripting (XSS)",
    ),
    (
        re.compile(r"(?i)(nikto|sqlmap|acunetix|havij|nmap|dirbuster|gobuster|wpscan|nuclei)"),
        "Automated Vulnerability Scanner",
    ),
]

ALERTED_CACHE: dict[str, float] = {}
STRIKE_HISTORY: dict[str, list[float]] = {}
BANNED_IPS: set[str] = set()


def send_telegram(message: str) -> bool:
    """Mengirim pesan peringatan ke satu atau beberapa Chat ID Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_IDS:
        print("[WARN] TELEGRAM_BOT_TOKEN atau TELEGRAM_CHAT_IDS belum dikonfigurasi.", file=sys.stderr)
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    any_sent = False

    for target in TELEGRAM_CHAT_IDS:
        payload = {
            "chat_id": target,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        try:
            req = urllib.request.Request(
                url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload).encode("utf-8"),
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    any_sent = True
        except Exception as exc:
            print(f"[ERROR] Gagal mengirim Telegram ke {target}: {exc}", file=sys.stderr)

    return any_sent


def maybe_ban_ip(ip: str) -> bool:
    """Memblokir IP secara otomatis via iptables jika AUTO_BAN_ENABLED aktif dan melewati ambang batas."""
    if not AUTO_BAN_ENABLED or ip in BANNED_IPS or not IP_VALID_RE.match(ip):
        return False

    now = time.time()
    recent = [ts for ts in STRIKE_HISTORY.get(ip, []) if now - ts <= AUTO_BAN_WINDOW_SECONDS]
    recent.append(now)
    STRIKE_HISTORY[ip] = recent

    if len(recent) < AUTO_BAN_THRESHOLD:
        return False

    iptables_bin = "/usr/sbin/iptables" if ":" not in ip else "/usr/sbin/ip6tables"
    if not os.path.exists(iptables_bin):
        return False

    check_cmd = [iptables_bin, "-C", "INPUT", "-s", ip, "-j", "DROP"]
    add_cmd = [iptables_bin, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]

    try:
        exists = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if exists.returncode != 0:
            subprocess.run(add_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        BANNED_IPS.add(ip)
        return True
    except Exception as exc:
        print(f"[ERROR] Gagal memblokir IP {ip} via iptables: {exc}", file=sys.stderr)
        return False


def escape_md_code(text: str) -> str:
    return text.replace("`", "'")


def notify_attack(ip: str, reason: str, uri: str, http_code: str, dry_run: bool = False) -> None:
    if ip in WHITELIST_IPS:
        return

    banned_now = False if dry_run else maybe_ban_ip(ip)

    now = time.time()
    last_seen = ALERTED_CACHE.get(ip, 0.0)
    if (now - last_seen < ALERT_COOLDOWN_SECONDS) and not banned_now:
        return
    ALERTED_CACHE[ip] = now

    sys.stdout.write(
        f"[INTERCEPTED {http_code}] IP: {ip} | Kategori: {reason} | URI: {uri[:160]}\n"
    )
    sys.stdout.flush()

    if dry_run:
        return

    timestamp_str = datetime.datetime.now().strftime(f"%Y-%m-%d %H:%M:%S {TIMEZONE_LABEL}").strip()
    server_info = (
        f"`{escape_md_code(SERVER_LABEL)}` (`{escape_md_code(SERVER_PUBLIC_IP)}`)"
        if SERVER_PUBLIC_IP and SERVER_PUBLIC_IP != "-"
        else f"`{escape_md_code(SERVER_LABEL)}`"
    )

    if http_code == "403":
        action_status = "HTTP 403 Forbidden Instan (Apache WAF)"
        footer = "Permintaan ditolak di level web server sebelum mencapai aplikasi/database."
    else:
        action_status = f"Terdeteksi pada Respons HTTP {escape_md_code(http_code)}"
        footer = "Pola mencurigakan tercatat pada access log; periksa aturan WAF untuk endpoint ini."

    if banned_now:
        action_status += " + IP Auto-Drop (iptables)"

    alert_text = (
        f"🛡️ *SIMPLE-DEFENSE: SERANGAN TERDETEKSI*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 *Target Server:* {server_info}\n"
        f"🛑 *Aksi Pertahanan:* *{action_status}*\n"
        f"⏰ *Waktu:* `{timestamp_str}`\n"
        f"👤 *IP Sumber:* `{escape_md_code(ip)}`\n"
        f"⚠️ *Kategori:* *{reason}*\n"
        f"🔍 *Payload / URI:*\n`{escape_md_code(uri[:180])}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ *Status:* {footer}"
    )
    send_telegram(alert_text)


def inspect_log_line(line: str, dry_run: bool = False) -> bool:
    decoded_line = urllib.parse.unquote(line)
    parts = line.split()
    if len(parts) < 9:
        return False

    ip = parts[0]
    req_uri = parts[6] if len(parts) > 6 else line[:120]
    http_code = parts[8]

    for regex, attack_name in ATTACK_PATTERNS:
        if regex.search(line) or regex.search(decoded_line):
            notify_attack(ip, attack_name, req_uri, http_code, dry_run=dry_run)
            return True
    return False


def open_tailed_files(paths: list[str]) -> dict[str, tuple[object, int]]:
    opened: dict[str, tuple[object, int]] = {}
    for path in paths:
        if os.path.exists(path):
            try:
                fh = open(path, "r", encoding="utf-8", errors="ignore")
                fh.seek(0, os.SEEK_END)
                ino = os.stat(path).st_ino
                opened[path] = (fh, ino)
            except OSError as exc:
                print(f"[WARN] Tidak dapat membuka log {path}: {exc}", file=sys.stderr)
    return opened


def refresh_rotated_files(
    paths: list[str], opened: dict[str, tuple[object, int]]
) -> None:
    """Membuka ulang berkas log apabila mengalami rotasi (logrotate) atau baru dibuat."""
    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            current_ino = os.stat(path).st_ino
        except OSError:
            continue

        if path not in opened:
            try:
                fh = open(path, "r", encoding="utf-8", errors="ignore")
                opened[path] = (fh, current_ino)
                print(f"[INFO] Mulai memantau berkas log baru: {path}", flush=True)
            except OSError:
                pass
        else:
            old_fh, old_ino = opened[path]
            if current_ino != old_ino:
                try:
                    old_fh.close()
                except Exception:
                    pass
                try:
                    new_fh = open(path, "r", encoding="utf-8", errors="ignore")
                    opened[path] = (new_fh, current_ino)
                    print(f"[INFO] Log rotation terdeteksi, membuka ulang: {path}", flush=True)
                except OSError:
                    opened.pop(path, None)


def monitor_logs(dry_run: bool = False) -> None:
    print(
        f"py-simpledefense daemon aktif | Server: {SERVER_LABEL} | "
        f"Memantau {len(LOG_FILES)} target log...",
        flush=True,
    )
    opened = open_tailed_files(LOG_FILES)
    last_rotation_check = time.time()

    while True:
        has_read = False
        for path, (fh, _ino) in list(opened.items()):
            while True:
                line = fh.readline()
                if not line:
                    break
                has_read = True
                inspect_log_line(line, dry_run=dry_run)

        now = time.time()
        if now - last_rotation_check >= 10.0:
            refresh_rotated_files(LOG_FILES, opened)
            last_rotation_check = now

        if not has_read:
            time.sleep(0.5)


def print_config_summary() -> int:
    print("=== Ringkasan Konfigurasi py-simpledefense ===")
    print(f"Server Label          : {SERVER_LABEL}")
    print(f"Server Public IP      : {SERVER_PUBLIC_IP}")
    print(f"Telegram Token Set    : {'YA' if TELEGRAM_BOT_TOKEN else 'BELUM'}")
    print(f"Telegram Chat Targets : {', '.join(TELEGRAM_CHAT_IDS) if TELEGRAM_CHAT_IDS else 'BELUM'}")
    print(f"Log Files ({len(LOG_FILES)})        : {', '.join(LOG_FILES)}")
    print(f"Whitelist IPs         : {', '.join(sorted(WHITELIST_IPS))}")
    print(f"Alert Cooldown        : {ALERT_COOLDOWN_SECONDS} detik")
    print(f"Auto-Ban iptables     : {'AKTIF' if AUTO_BAN_ENABLED else 'NONAKTIF (Hybrid WAF Mode)'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="py-simpledefense: Hybrid Apache WAF & Real-Time Telegram Alert Daemon"
    )
    parser.add_argument(
        "--test-alert",
        action="store_true",
        help="Kirim pesan uji coba ke Telegram dan keluar",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Tampilkan ringkasan konfigurasi aktif tanpa menjalankan daemon",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Pantau log dan cetak deteksi ke stdout tanpa mengirim Telegram atau auto-ban",
    )
    args = parser.parse_args()

    if args.check_config:
        return print_config_summary()

    if args.test_alert:
        print("Menguji pengiriman notifikasi Telegram...")
        ok = send_telegram(
            f"🛡️ *py-simpledefense Test Alert*\n"
            f"Sistem pertahanan aktif hybrid pada `{escape_md_code(SERVER_LABEL)}` siap beroperasi."
        )
        print("Hasil uji kirim:", "BERHASIL" if ok else "GAGAL")
        return 0 if ok else 1

    monitor_logs(dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
