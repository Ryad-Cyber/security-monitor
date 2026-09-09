import os
import smtplib
import json
import urllib.request
import time
from email.message import EmailMessage


def load_env():
    env_file = "/home/boujenan/security-monitor/.env"

    try:
        with open(env_file) as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                os.environ[key] = value.strip()

    except FileNotFoundError:
        pass


load_env()


def send_email_alert(subject, message):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    alert_email = os.getenv("ALERT_EMAIL")

    if not all([smtp_host, smtp_user, smtp_password, alert_email]):
        print("⚠️ Configuration email absente. Aucune alerte envoyée.")
        return

    email = EmailMessage()
    email["Subject"] = subject
    email["From"] = smtp_user
    email["To"] = alert_email
    email.set_content(message)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(email)

        print("📧 Alerte email envoyée.")

    except Exception as e:
        print(f"❌ Échec de l'envoi de l'alerte : {e}")


def send_ilert_alert(summary):
    integration_key = os.getenv("ILERT_INTEGRATION_KEY")

    if not integration_key:
        print("⚠️ Clé iLert absente. Aucune alerte iLert envoyée.")
        return

    url = "https://api.ilert.com/api/events"

    payload = {
        "integrationKey": integration_key,
        "eventType": "ALERT",
        "alertKey": f"nmap-{int(time.time())}",
        "summary": summary,
        "priority": "HIGH"
    }

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            print(f"🚨 Alerte iLert envoyée (HTTP {response.status}).")
            print(f"Réponse iLert : {body}")

    except Exception as e:
        print(f"❌ Échec de l'envoi iLert : {e}")
