#!/usr/bin/env bash
# ==============================================================================
# py-simpledefense - Installer & Hardening Script (Ubuntu / Debian)
# Memasang Apache Global WAF, MariaDB Hardening, dan Daemon Alert Telegram
# ==============================================================================
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/py-simpledefense"
CONFIG_DIR="/etc/py-simpledefense"
CONFIG_FILE="${CONFIG_DIR}/config.env"
SERVICE_DEST="/etc/systemd/system/py-simpledefense.service"
APACHE_CONF_DEST="/etc/apache2/conf-available/py-simpledefense-waf.conf"

if [[ "${EUID}" -ne 0 ]]; then
    echo "[-] Error: Jalankan installer ini sebagai root (contoh: sudo bash deploy_defense.sh)"
    exit 1
fi

echo "[*] 1. Menyiapkan direktori instalasi & konfigurasi..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"
cp -f "${BASE_DIR}/csirt_active_defense.py" "${INSTALL_DIR}/csirt_active_defense.py"
chmod 750 "${INSTALL_DIR}/csirt_active_defense.py"

if [[ ! -f "${CONFIG_FILE}" ]]; then
    if [[ -f "${BASE_DIR}/.env" ]]; then
        cp "${BASE_DIR}/.env" "${CONFIG_FILE}"
        echo "    -> Menyalin konfigurasi dari .env lokal ke ${CONFIG_FILE}"
    else
        cp "${BASE_DIR}/.env.example" "${CONFIG_FILE}"
        echo "    -> Membuat template baru di ${CONFIG_FILE} (silakan isi TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_IDS)"
    fi
fi
chmod 600 "${CONFIG_FILE}"

echo "[*] 2. Memasang aturan Apache Global WAF (jika Apache2 terpasang)..."
if command -v apache2ctl >/dev/null 2>&1 && [[ -d "/etc/apache2/conf-available" ]]; then
    a2enmod rewrite headers >/dev/null 2>&1 || true
    cp -f "${BASE_DIR}/configs/apache-global-waf.conf" "${APACHE_CONF_DEST}"
    a2enconf py-simpledefense-waf >/dev/null 2>&1 || true
    if apache2ctl configtest; then
        systemctl reload apache2
        echo "    -> Apache Global WAF aktif dan konfigurasi valid."
    else
        echo "[!] Peringatan: apache2ctl configtest gagal, menonaktifkan sementara conf baru."
        a2disconf py-simpledefense-waf >/dev/null 2>&1 || true
        exit 1
    fi
else
    echo "    -> Apache2 tidak ditemukan, melewati pemasangan conf Apache."
fi

echo "[*] 3. Memasang hardening MariaDB/MySQL (secure_file_priv & localhost bind)..."
if [[ -d "/etc/mysql/mariadb.conf.d" ]] || [[ -d "/etc/mysql/conf.d" ]]; then
    mkdir -p /var/lib/mysql-files
    chown mysql:mysql /var/lib/mysql-files 2>/dev/null || true
    chmod 700 /var/lib/mysql-files

    if [[ -d "/etc/mysql/mariadb.conf.d" ]]; then
        cp -f "${BASE_DIR}/configs/99-mariadb-hardening.cnf" /etc/mysql/mariadb.conf.d/99-mariadb-hardening.cnf
    else
        cp -f "${BASE_DIR}/configs/99-mariadb-hardening.cnf" /etc/mysql/conf.d/99-mariadb-hardening.cnf
    fi
    echo "    -> Konfigurasi hardening database disalin (restart mariadb/mysql secara terjadwal bila diperlukan)."
else
    echo "    -> Direktori konfigurasi MySQL/MariaDB tidak ditemukan, dilewati."
fi

echo "[*] 4. Mendaftarkan dan menjalankan service systemd py-simpledefense..."
cp -f "${BASE_DIR}/systemd/py-simpledefense.service" "${SERVICE_DEST}"
chmod 644 "${SERVICE_DEST}"
systemctl daemon-reload
systemctl enable py-simpledefense.service
systemctl restart py-simpledefense.service

echo "[*] 5. Status layanan py-simpledefense:"
systemctl status py-simpledefense.service --no-pager -l | head -n 14 || true

echo ""
echo "[OK] Instalasi py-simpledefense selesai!"
echo "     Edit konfigurasi : sudo nano ${CONFIG_FILE}"
echo "     Uji notifikasi   : sudo SIMPLEDEFENSE_ENV=${CONFIG_FILE} python3 ${INSTALL_DIR}/csirt_active_defense.py --test-alert"
echo "     Restart service  : sudo systemctl restart py-simpledefense"
