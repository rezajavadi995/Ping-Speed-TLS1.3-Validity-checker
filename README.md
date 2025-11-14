# Ping-Speed-TLS1.3-Validity-checker
# SNI Checker Bot

🚀 **SNI Checker Bot** is a fast and reliable Telegram bot for checking Ping, Speed, and TLS validity of servers.

---

## Features

- Check server ping and speed automatically
- Validate TLS 1.3 configuration
- Real-time results via Telegram bot
- Auto scheduler to run checks periodically
- Simple setup with systemd service for auto-start

---

## Fast Install (1 Command)

Install and configure the bot with just one command:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/rezajavadi995/Ping-Speed-TLS1.3-Validity-checker/main/install.sh)
```
---

## What happens:

1. Installs required packages (python3, pip, venv, etc.)


2. Sets up a virtual environment


3. Installs Python dependencies from requirements.txt


4. Prompts you to enter your Telegram Bot Token


5. Creates .env file automatically


6. Sets up a systemd service to run the bot in the background

---
Check bot status:
```
sudo systemctl status sni-checker.service
```

View logs in real-time:
```
sudo journalctl -u sni-checker.service -f
```

Restart the bot:
```
sudo systemctl restart sni-checker.service
```
---

Getting Your Telegram Bot Token

1. Open BotFather on Telegram


2. Use /newbot to create a new bot


3. Copy the generated token


4. Enter it when prompted during installation


---

Configuration

The .env file is created automatically in /opt/ping-speed-tls-checker/.
It contains:

TELEGRAM_TOKEN=YOUR_BOT_TOKEN_HERE

---

Uninstall

If you want to remove the bot:
```
sudo systemctl stop sni-checker.service
```
```
sudo systemctl disable sni-checker.service
```
```
rm -rf /opt/ping-speed-tls-checker
```
---

Support

If you encounter issues:

Check the logs: ```sudo journalctl -u sni-checker.service -f```

Make sure Python dependencies are installed correctly

Ensure your .env file has a valid Telegram token

---

License

MIT License

---
