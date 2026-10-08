"""
Input Parsing and Validation Module.
Handles target host resolution and port string parsing (ranges, lists, presets).
"""

import ipaddress
import re
import socket
from typing import List, Optional, Tuple

from .services import TOP_20_PORTS, TOP_100_PORTS


class TargetResolutionError(Exception):
    """Raised when a hostname cannot be resolved to an IP address."""
    pass


class InvalidPortSpecificationError(Exception):
    """Raised when the user provides an invalid port string or out-of-range port."""
    pass


def resolve_target(target: str) -> Tuple[str, str]:
    """
    Resolve a target host (IP or FQDN) to an IPv4 address and canonical hostname.

    Returns:
        Tuple of (ip_address, hostname)

    Raises:
        TargetResolutionError: If target cannot be resolved.
    """
    clean_target = target.strip()
    if not clean_target:
        raise TargetResolutionError("Target hostname or IP address cannot be empty.")

    # Strip protocol prefix if accidentally supplied (e.g., http://localhost)
    clean_target = re.sub(r"^https?://", "", clean_target, flags=re.IGNORECASE)
    clean_target = clean_target.split("/")[0].split(":")[0]  # Remove trailing path or port

    # Check if target is already a valid IP address
    try:
        ip_obj = ipaddress.ip_address(clean_target)
        # Attempt reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(str(ip_obj))[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = str(ip_obj)
        return str(ip_obj), hostname
    except ValueError:
        pass

    # Target is a hostname - perform DNS forward lookup
    try:
        resolved_ip = socket.gethostbyname(clean_target)
        return resolved_ip, clean_target
    except socket.gaierror as exc:
        raise TargetResolutionError(
            f"Failed to resolve hostname '{clean_target}': {exc.strerror}"
        ) from exc


def parse_ports(port_arg: Optional[str] = None, top_n: Optional[int] = None) -> List[int]:
    """
    Parse a flexible port specification into a sorted, unique list of integers.

    Supported formats:
        - top_n: 20 or 100
        - presets: "top20", "top100", "common" (1-1024), "all" (1-65535)
        - single port: "80"
        - range: "1-100"
        - list: "22,80,443"
        - mixed: "22,80-85,443,8080"

    Returns:
        List[int]: Sorted list of valid port numbers (1-65535).
    """
    if top_n is not None:
        if top_n <= 20:
            return sorted(set(TOP_20_PORTS[:top_n]))
        elif top_n <= 100:
            return sorted(set(TOP_100_PORTS[:top_n]))
        else:
            raise InvalidPortSpecificationError(
                f"Top N must be between 1 and 100. Received: {top_n}"
            )

    if not port_arg or not port_arg.strip():
        # Default behavior: Common privileged ports 1-1024
        return list(range(1, 1025))

    clean_arg = port_arg.strip().lower()

    # Check presets
    if clean_arg in ("top20", "top-20"):
        return sorted(set(TOP_20_PORTS))
    if clean_arg in ("top100", "top-100"):
        return sorted(set(TOP_100_PORTS))
    if clean_arg in ("common", "default"):
        return list(range(1, 1025))
    if clean_arg == "all":
        return list(range(1, 65536))

    ports_set = set()
    segments = [seg.strip() for seg in clean_arg.split(",") if seg.strip()]

    if not segments:
        raise InvalidPortSpecificationError("No valid ports specified.")

    for segment in segments:
        if "-" in segment:
            parts = segment.split("-")
            if len(parts) != 2:
                raise InvalidPortSpecificationError(
                    f"Invalid range segment '{segment}'. Format must be start-end (e.g., 80-100)."
                )
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
            except ValueError as exc:
                raise InvalidPortSpecificationError(
                    f"Port numbers in range '{segment}' must be integers."
                ) from exc

            if start > end:
                raise InvalidPortSpecificationError(
                    f"Range start ({start}) cannot be greater than range end ({end})."
                )
            if start < 1 or end > 65535:
                raise InvalidPortSpecificationError(
                    f"Port range {start}-{end} outside valid boundaries (1-65535)."
                )

            ports_set.update(range(start, end + 1))
        else:
            try:
                port = int(segment)
            except ValueError as exc:
                raise InvalidPortSpecificationError(
                    f"Invalid port number '{segment}'. Must be an integer."
                ) from exc

            if port < 1 or port > 65535:
                raise InvalidPortSpecificationError(
                    f"Port {port} outside valid boundary (1-65535)."
                )
            ports_set.add(port)

    return sorted(ports_set)
