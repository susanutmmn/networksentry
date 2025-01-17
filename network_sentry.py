import os
import time
import socket
import threading
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from scapy.all import sniff, ARP

# Configuration
ALERT_EMAIL = "your_email@example.com"
ALERT_PASSWORD = "your_email_password"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
TARGET_EMAIL = "target_email@example.com"
INTERFACE = "eth0"
TRUSTED_MACS = ["00:14:22:01:23:45", "00:25:96:FF:FE:12:34:56"]

def send_email_alert(subject, body):
    msg = MIMEMultipart()
    msg['From'] = ALERT_EMAIL
    msg['To'] = TARGET_EMAIL
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(ALERT_EMAIL, ALERT_PASSWORD)
    text = msg.as_string()
    server.sendmail(ALERT_EMAIL, TARGET_EMAIL, text)
    server.quit()

def alert_intrusion(mac_address, ip_address):
    subject = "Network Intrusion Alert!"
    body = f"Unrecognized device detected:\n\nMAC Address: {mac_address}\nIP Address: {ip_address}\nTime: {datetime.now()}"
    print(body)
    send_email_alert(subject, body)

def detect_arp_spoof(packet):
    if packet.haslayer(ARP):
        if packet[ARP].op == 1:  # who-has (request)
            mac_address = packet[ARP].hwsrc
            ip_address = packet[ARP].psrc
            if mac_address not in TRUSTED_MACS:
                alert_intrusion(mac_address, ip_address)

def start_sniffing():
    print("Starting Network Sentry...")
    sniff(iface=INTERFACE, store=False, prn=detect_arp_spoof)

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\nStopping Network Sentry...")
        exit(0)