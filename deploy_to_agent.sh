#!/usr/bin/env bash
# ==============================================================================
# Helper Orchestrator Deployment py-simpledefense ke Remote Server
# Digunakan oleh SecOps Agent begitu SSH public key terdaftar di host target
# ==============================================================================
set -euo pipefail

TARGET_HOST="${1:-}"
TARGET_IP="${2:-}"
SERVER_LABEL="${3:-$TARGET_HOST}"

if [[ -z "${TARGET_HOST}" || -z "${TARGET_IP}" ]]; then
    echo "Usage: $0 <user@host_or_ip> <public_ip> [server_label]"
    echo "Contoh: $0 sandi@server-target.local 203.0.113.10 server.contoh.go.id"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Token bot KHUSUS alert (bukan token bot Hermes) - pisahkan blast radius.
# Isi file ini (chmod 600) dengan baris: SIMPLEDEFENSE_BOT_TOKEN=<token dari @BotFather>
ALERT_ENV="/home/sandi/.hermes/secrets/simpledefense.env"

if [[ ! -f "${ALERT_ENV}" ]]; then
    echo "[-] File ${ALERT_ENV} belum ada. Buat bot alert khusus di @BotFather lebih dulu."
    exit 1
fi

TELEGRAM_TOKEN=$(grep "^SIMPLEDEFENSE_BOT_TOKEN=" "${ALERT_ENV}" | cut -d'=' -f2- | tr -d '"' | tr -d "'")
if [[ -z "${TELEGRAM_TOKEN}" ]]; then
    echo "[-] SIMPLEDEFENSE_BOT_TOKEN kosong di ${ALERT_ENV}."
    exit 1
fi

echo "[*] 1. Menguji koneksi SSH ke ${TARGET_HOST}..."
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "${TARGET_HOST}" "echo 'SSH Connection OK'" 2>/dev/null; then
    echo "[-] Kunci SSH belum terdaftar atau koneksi ditolak di ${TARGET_HOST}."
    exit 2
fi

echo "[*] 2. Menyiapkan paket & environment..."
STAGE_DIR=$(mktemp -d /tmp/defense-stage.XXXXXX)
cp -r "${SCRIPT_DIR}/." "${STAGE_DIR}/"

cat << ENV_EOF > "${STAGE_DIR}/.env"
SERVER_LABEL=${SERVER_LABEL}
SERVER_PUBLIC_IP=${TARGET_IP}
TIMEZONE_LABEL=WITA
TELEGRAM_BOT_TOKEN=${TELEGRAM_TOKEN}
TELEGRAM_CHAT_IDS=123456789,@nama_channel_csirt
LOG_FILES=/var/log/apache2/*access*.log,/var/log/nginx/*access*.log,/var/log/apache2/access.log
WHITELIST_IPS=127.0.0.1,::1
AUTO_BAN_ENABLED=false
AUTO_BAN_THRESHOLD=10
AUTO_BAN_WINDOW_SECONDS=120
ENV_EOF

echo "[*] 3. Mengunggah paket ke ${TARGET_HOST}:/tmp/py-simpledefense..."
ssh "${TARGET_HOST}" "rm -rf /tmp/py-simpledefense"
scp -q -r "${STAGE_DIR}" "${TARGET_HOST}:/tmp/py-simpledefense"
rm -rf "${STAGE_DIR}"

echo "[*] 4. Menjalankan installer deploy_defense.sh di remote host..."
ssh -t "${TARGET_HOST}" "sudo bash /tmp/py-simpledefense/deploy_defense.sh && rm -rf /tmp/py-simpledefense"

echo "[*] 5. Menjalankan uji alert notifikasi..."
ssh "${TARGET_HOST}" "sudo SIMPLEDEFENSE_ENV=/etc/py-simpledefense/config.env python3 /opt/py-simpledefense/csirt_active_defense.py --test-alert"

echo "[OK] Deployment py-simpledefense pada ${TARGET_HOST} selesai & terverifikasi!"
