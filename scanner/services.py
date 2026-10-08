"""
Port to Service Mapping Module.
Provides known service definitions and port resolution logic.
"""

import socket
from typing import Dict, List

# Dictionary of well-known and common ports with human-readable service names
KNOWN_SERVICES: Dict[int, str] = {
    7: "Echo",
    9: "Discard",
    13: "Daytime",
    19: "Chargen",
    20: "FTP-Data",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer)",
    37: "Time",
    43: "WHOIS",
    53: "DNS (Domain Name System)",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP (Trivial FTP)",
    70: "Gopher",
    79: "Finger",
    80: "HTTP (World Wide Web)",
    88: "Kerberos",
    102: "MS Exchange / ISO-TSAP",
    110: "POP3 (Post Office Protocol v3)",
    111: "RPCBind / Sun RPC",
    119: "NNTP (Usenet)",
    123: "NTP (Network Time Protocol)",
    135: "MS RPC / Endpoint Mapper",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access Protocol)",
    161: "SNMP (Simple Network Mgmt)",
    162: "SNMP Trap",
    177: "XDMCP",
    179: "BGP (Border Gateway Protocol)",
    194: "IRC (Internet Relay Chat)",
    389: "LDAP (Lightweight Directory Access)",
    443: "HTTPS (HTTP Secure / TLS)",
    445: "SMB / Microsoft-DS (Active Directory)",
    465: "SMTPS (SMTP over SSL)",
    500: "ISAKMP / IKE (IPsec VPN)",
    514: "Syslog",
    515: "LPD (Line Printer Daemon)",
    520: "RIP (Routing Information Protocol)",
    587: "SMTP (Message Submission)",
    631: "IPP (Internet Printing Protocol / CUPS)",
    636: "LDAPS (LDAP over SSL)",
    873: "Rsync",
    993: "IMAPS (IMAP over SSL)",
    995: "POP3S (POP3 over SSL)",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "Microsoft SQL Server",
    1434: "MS SQL Monitor",
    1521: "Oracle Database",
    1723: "PPTP VPN",
    1883: "MQTT (Message Queuing Telemetry)",
    2049: "NFS (Network File System)",
    2082: "cPanel default",
    2083: "cPanel SSL",
    2181: "Apache ZooKeeper",
    2375: "Docker REST API (Plain)",
    2376: "Docker REST API (TLS)",
    3000: "Node.js / React / Grafana Dev Server",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    4200: "Angular Dev Server",
    5000: "Flask / Python Web App / Docker Registry",
    5432: "PostgreSQL Database",
    5672: "RabbitMQ Message Broker",
    5900: "VNC (Virtual Network Computing)",
    5985: "WinRM HTTP (Windows Remote Mgmt)",
    5986: "WinRM HTTPS (Windows Remote Mgmt)",
    6379: "Redis In-Memory Database",
    6443: "Kubernetes API Server",
    7000: "Cassandra Inter-Node Cluster",
    8000: "HTTP Alternate / Django / Python SimpleHTTP",
    8080: "HTTP Proxy / Apache Tomcat / Spring Boot",
    8081: "HTTP Alternate / Sun Proxy",
    8443: "HTTPS Alternate / Apache Tomcat SSL",
    8888: "Jupyter Notebook / HTTP Alternate",
    9000: "SonarQube / PHP-FPM / Portainer",
    9090: "Prometheus Monitoring Server",
    9092: "Apache Kafka",
    9200: "Elasticsearch REST API",
    9300: "Elasticsearch Node-to-Node",
    11211: "Memcached",
    27017: "MongoDB Database",
    27018: "MongoDB Sharding",
    28017: "MongoDB Web Status",
    50000: "SAP / DB2",
}

# Top 20 most frequently targeted / scanned ports
TOP_20_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

# Top 100 common ports (industry standard Nmap top 100 subset)
TOP_100_PORTS: List[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090,
    9100, 9200, 9999, 10000, 27017, 32768, 49152
]


def get_service_name(port: int, proto: str = "tcp") -> str:
    """
    Resolve a port number to its corresponding service name.
    
    1. Checks the curated KNOWN_SERVICES dictionary.
    2. Falls back to operating system service resolver via socket.getservbyport.
    3. Defaults to 'Unknown Service' if not resolvable.
    """
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]

    try:
        return socket.getservbyport(port, proto).upper()
    except (OSError, socket.error):
        return "Unknown Service"
