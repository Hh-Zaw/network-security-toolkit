# network-security-toolkit
Python-based network security tools for port scanning, service detection, and vulnerability assessment


# Network Security Toolkit 🔒

A collection of Python-based network security tools for ethical hacking and security assessments.

## 🚀 Features

### Port Scanner
- Multi-threaded for fast scanning
- Service detection
- Custom port range support
- Clean output format

## 📋 Requirements
- Python 3.6+
- Standard library only (no external dependencies)

## 🔧 Installation
```bash
git clone https://github.com/Hh-Zaw/network-security-toolkit.git
cd network-security-toolkit

# Scan default ports (1-1000)
python3 port_scanner.py example.com

# Scan specific port range
python3 port_scanner.py example.com -p 1-65535

# Adjust thread count for faster scanning
python3 port_scanner.py example.com -t 200
