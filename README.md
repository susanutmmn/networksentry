# NetworkSentry

NetworkSentry is a Python-based security tool designed to monitor network traffic on Windows systems, detect unauthorized network access, and alert users to potential intrusions.

## Features

- Monitors network traffic for ARP spoofing attacks.
- Sends email alerts when unauthorized devices are detected.
- Customizable trusted MAC address list.

## Requirements

- Python 3.x
- [Scapy](https://scapy.net/) library
- Email account with SMTP access for sending alerts

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/NetworkSentry.git
   ```

2. Navigate to the project directory:
   ```bash
   cd NetworkSentry
   ```

3. Install the required Python package:
   ```bash
   pip install scapy
   ```

4. Update the configuration section in `network_sentry.py` with your email credentials, target email, and network interface.

## Usage

Run the program with administrative privileges to start network monitoring:

```bash
python network_sentry.py
```

## Configuration

- `ALERT_EMAIL`: The email address used to send alerts.
- `ALERT_PASSWORD`: The password for the alert email account.
- `SMTP_SERVER`: The SMTP server for the alert email.
- `SMTP_PORT`: The port for the SMTP server.
- `TARGET_EMAIL`: The recipient email address for alerts.
- `INTERFACE`: The network interface to monitor.
- `TRUSTED_MACS`: A list of trusted MAC addresses.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit a pull request or reach out for major changes.

## Disclaimer

Use this tool responsibly and only on networks you own or have explicit permission to monitor. Unauthorized use is prohibited.