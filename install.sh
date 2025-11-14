#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/rezajavadi995/Ping-Speed-TLS1.3-Validity-checker.git"
REPO_DIR="/opt/ping-speed-tls-checker"
SERVICE_NAME="sni-checker.service"
VENV_DIR="$REPO_DIR/venv"

echo "=== شروع نصب پروژه ==="

# نیازمندی‌های سیستم (برای دبیان/اوبونتو)
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y python3 python3-venv python3-pip git curl
fi

# کلون ریپو
if [ -d "$REPO_DIR" ]; then
  echo "پوشه $REPO_DIR موجود است، آن را به‌روزرسانی می‌کنم..."
  cd "$REPO_DIR"
  git pull
else
  sudo git clone "$REPO_URL" "$REPO_DIR"
  sudo chown -R "$(whoami)":"$(whoami)" "$REPO_DIR"
  cd "$REPO_DIR"
fi

# محیط مجازی
python3 -m venv "$VENV_DIR"
# فعال‌سازی و ارتقا pip
"$VENV_DIR/bin/python" -m pip install --upgrade pip

# نصب نیازمندی‌ها (در صورت نبود requirements.txt، حداقل پکیج‌های اصلی را نصب کن)
if [ -f requirements.txt ]; then
  "$VENV_DIR/bin/pip" install -r requirements.txt
else
  "$VENV_DIR/bin/pip" install python-telegram-bot "python-telegram-bot[job-queue]" "httpx[http2]" python-dotenv
fi


echo
echo "لطفاً توکن ربات تلگرام خود را وارد کنید (از BotFather):"
read -rp "TELEGRAM_TOKEN: " USER_TOKEN
if [ -z "$USER_TOKEN" ]; then
  echo "توکن خالی است — نصب متوقف شد."
  exit 1
fi

# ایجاد فایل .env
cat > "$REPO_DIR/.env" <<EOF
TELEGRAM_TOKEN=$USER_TOKEN
EOF

echo ".env ساخته شد."

# ساخت systemd service
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
sudo tee "$SERVICE_PATH" >/dev/null <<EOF
[Unit]
Description=SNI Checker Bot
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$REPO_DIR
EnvironmentFile=$REPO_DIR/.env
ExecStart=$VENV_DIR/bin/python $REPO_DIR/SNI.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ری‌لود systemd، فعال‌سازی و استارت سرویس
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

echo "=== نصب کامل شد ==="
echo "برای مشاهده وضعیت سرویس: sudo systemctl status $SERVICE_NAME"
echo "لاگ‌ها: sudo journalctl -u $SERVICE_NAME -f"
