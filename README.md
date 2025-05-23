# network-security-toolkit
Python-based network security tools for port scanning, service detection, and vulnerability assessment


# Scan default ports (1-1000)
python3 port_scanner.py example.com

# Scan specific port range
python3 port_scanner.py example.com -p 1-65535

# Adjust thread count for faster scanning
python3 port_scanner.py example.com -t 200
