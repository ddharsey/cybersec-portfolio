"""
Simple Port Scanner
Author: Daiyaan Dharsey
Description: A beginner-friendly TCP port scanner that checks common service ports
             on a target host and reports their open/closed status.
Usage:
    python SimplePortScanner.py
"""

import socket

# Dictionary mapping common port numbers to their service names
# These are frequently targeted ports in security assessments
PORT_NAMES = {
    21: "FTP",       # File Transfer Protocol — file sharing, often unencrypted
    22: "SSH",       # Secure Shell — encrypted remote access
    23: "Telnet",    # Telnet — unencrypted remote access (legacy, insecure)
    80: "HTTP",      # Hypertext Transfer Protocol — web traffic (unencrypted)
    443: "HTTPS",    # HTTP Secure — encrypted web traffic (TLS/SSL)
    445: "SMB",      # Server Message Block — Windows file sharing (common attack vector)
    3389: "RDP",     # Remote Desktop Protocol — Windows remote access
}

# Iterate through each port defined in our dictionary
for port in PORT_NAMES:

    # Create a new TCP socket for each port
    # AF_INET = IPv4 addressing, SOCK_STREAM = TCP connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set timeout to 0.5 seconds — prevents hanging on filtered/unresponsive ports
    s.settimeout(0.5)

    # Attempt to connect to the target on the current port
    # connect_ex() returns 0 on success, error code on failure
    # Target: 127.0.0.1 (localhost) — change this to scan other hosts
    status = s.connect_ex(("127.0.0.1", port))

    # Check the connection result and report status
    if status == 0:
        print(f"{port} IS OPEN. SERVICE: {PORT_NAMES[port]}")
    else:
        print(f"{port} IS CLOSED. SERVICE: {PORT_NAMES[port]}")

    # Close the socket to free up system resources
    s.close()
