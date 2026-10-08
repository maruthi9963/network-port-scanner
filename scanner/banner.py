"""
Banner Grabbing and Service Fingerprinting Module.
Connects to open ports and probes for service banners and version information.
"""

import re
import socket
from typing import Optional


# Known probes tailored to specific services/ports
PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    3000: b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    5000: b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    6379: b"PING\r\n",
}


def sanitize_banner(raw_data: bytes) -> str:
    """
    Clean raw socket response bytes into a concise, readable string.
    Extracts HTTP Server headers or the first meaningful line.
    """
    text = raw_data.decode("utf-8", errors="replace").strip()
    if not text:
        return ""

    # Check for HTTP response
    if "HTTP/" in text:
        # Search for Server header
        server_match = re.search(r"Server:\s*([^\r\n]+)", text, re.IGNORECASE)
        status_match = re.match(r"(HTTP/\d\.\d\s+\d{3}[^\r\n]*)", text)
        if server_match:
            server_info = server_match.group(1).strip()
            status_info = status_match.group(1).strip() if status_match else ""
            return f"{status_info} (Server: {server_info})" if status_info else f"Server: {server_info}"
        elif status_match:
            return status_match.group(1).strip()

    # Extract first non-empty line
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines:
        first_line = lines[0]
        # Truncate if excessively long
        return first_line[:120] + ("..." if len(first_line) > 120 else "")

    return ""


def grab_banner(target_ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """
    Attempt to grab a service banner from an open TCP port.

    Args:
        target_ip: The target IPv4 address.
        port: The open port number.
        timeout: Socket read timeout in seconds.

    Returns:
        str or None: Cleaned banner string if obtained, else None.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # Check if port expects a client probe (like HTTP or Redis)
        probe = PROBES.get(port)
        if probe:
            sock.sendall(probe)
        else:
            # For services like SSH (22), FTP (21), SMTP (25), greeting is sent immediately.
            # Try waiting for an unsolicited banner first.
            sock.settimeout(min(timeout, 0.6))
            try:
                data = sock.recv(1024)
                if data:
                    banner = sanitize_banner(data)
                    if banner:
                        return banner
            except (socket.timeout, OSError):
                # If no unsolicited banner received, send a generic probe
                pass

            try:
                sock.settimeout(timeout)
                sock.sendall(b"\r\nHELP\r\n")
            except OSError:
                return None

        # Read response to probe
        try:
            data = sock.recv(1024)
            if data:
                banner = sanitize_banner(data)
                return banner if banner else None
        except (socket.timeout, OSError):
            return None

    except (socket.error, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return None
