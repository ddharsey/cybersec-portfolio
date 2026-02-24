# Simple Port Scanner

A beginner-friendly TCP port scanner that checks common service ports on a target host and reports whether they are open or closed.

## How It Works

The scanner creates a TCP socket connection to each port in the target list. If the connection succeeds (returns 0), the port is open and a service is likely running. If it fails, the port is closed or filtered.

## Ports Scanned

| Port | Service | Description |
|------|---------|-------------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell (remote access) |
| 23 | Telnet | Unencrypted remote access (legacy) |
| 80 | HTTP | Web traffic |
| 443 | HTTPS | Encrypted web traffic |
| 445 | SMB | Windows file sharing |
| 3389 | RDP | Remote Desktop Protocol |

## Usage

```bash
python SimplePortScanner.py
```

By default the scanner targets `127.0.0.1` (localhost). To scan a different host, change the IP address on this line in the script:

```python
status = s.connect_ex(("127.0.0.1", port))
```

## Example Output

```
21 IS CLOSED. SERVICE: FTP
22 IS CLOSED. SERVICE: SSH
23 IS CLOSED. SERVICE: Telnet
80 IS CLOSED. SERVICE: HTTP
443 IS OPEN. SERVICE: HTTPS
445 IS OPEN. SERVICE: SMB
3389 IS CLOSED. SERVICE: RDP
```

## Concepts Demonstrated

- Python socket programming (`socket.AF_INET`, `socket.SOCK_STREAM`)
- TCP connection handling with `connect_ex()`
- Timeout configuration for network operations
- Common service port identification

## See Also

For a more advanced version with multi-threading, banner grabbing, flexible port ranges, and CLI arguments, see the [Port Scanner](../tools/) in the `tools/` directory.

## Legal Disclaimer

This tool is intended for **authorised security testing and educational purposes only**. Only scan systems you own or have explicit written permission to test.
