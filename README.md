# High-Performance TCP Port Scanner & Reconnaissance Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-Standard%20Library%20Only-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-23%20passed-success.svg)]()
[![License](https://img.shields.io/badge/license-MIT-purple.svg)]()

A modular, multi-threaded TCP network reconnaissance tool developed in Python using low-level socket programming. Engineered to rapidly identify open network ports, profile service latency, extract service banners (software version fingerprinting), and export audit logs for security analysis.

---

## 🌟 Key Features

- **Multi-Threaded Concurrency Engine**: Leverages `concurrent.futures.ThreadPoolExecutor` with configurable worker pools (10 to 500+ threads) to scan thousands of ports in seconds.
- **Pure Standard Library**: Zero third-party dependencies required. Built directly on Python's native `socket`, `concurrent.futures`, `ipaddress`, and `argparse` modules.
- **Active Banner Grabbing**: Probes open ports for protocol-specific banners (SSH versions, HTTP Server headers, FTP greetings, Redis status) for vulnerability fingerprinting.
- **Accurate State Detection**: Distinguishes between **OPEN** (established 3-way handshake), **CLOSED** (TCP RST packet received), and **FILTERED** (silent drop by firewall or packet filter).
- **Flexible Port Specification**:
  - Ranges: `-p 1-1024` or `-p 80-90`
  - Comma-delimited lists: `-p 22,80,443,3306,8080`
  - Presets: `--top 20`, `--top 100`, `-p common`, or `-p all`
- **Comprehensive Service Mapping**: Built-in dictionary containing modern web, database, cloud, container, and infrastructure services with OS-level `socket.getservbyport` fallback.
- **Rich Terminal UX**: Single-line animated progress bar, formatted tabular output with ANSI colors, and latency metrics.
- **Multi-Format Export**: One-click report generation to **JSON** (`-j report.json`) and **CSV/Text** (`-o report.txt` / `-o report.csv`).

---

## 🏗️ Architecture & How It Works

### TCP Handshake Scanning Cycle

```
[Port Scanner Client]                     [Target Host]
         |                                      |
         | -------- 1. TCP SYN ------------->   |
         |                                      |
   (If Port is OPEN):                           |
         | <------- 2. TCP SYN-ACK -----------  |
         | -------- 3. TCP ACK ------------->   |  ==> Connection Established (State: OPEN)
         |                                      |
   (Banner Probe Phase):                        |
         | -------- 4. Service Probe ------->   |  (e.g., HEAD / HTTP/1.0 or SSH greeting)
         | <------- 5. Banner Response ------   |  ==> Fingerprinted (e.g., Apache/2.4)
         | -------- 6. TCP FIN / RST ------->   |  ==> Clean Connection Termination
         |                                      |
   (If Port is CLOSED):                         |
         | <------- TCP RST, ACK ------------   |  ==> Port Closed (WSAECONNREFUSED / 10061)
         |                                      |
   (If Port is FILTERED):                       |
         | ....... (Packet Dropped) .........   |  ==> Socket Timeout (WSAETIMEDOUT / 10060)
```

### Module Breakdown

```
tcp-port-scanner/
├── scanner/
│   ├── __init__.py      # Package entry & version metadata
│   ├── core.py          # PortScanner engine, thread worker pool, connection lifecycle
│   ├── banner.py        # Protocol-specific probes & banner sanitization
│   ├── services.py      # Curated port-to-service dictionary & top port lists
│   ├── parser.py        # Target resolution (FQDN/IP) & port syntax parser
│   └── reporter.py      # Console rendering, ANSI colors, progress bars, JSON/CSV exports
├── tests/
│   ├── test_parser.py   # Unit tests for port ranges, lists, shortcuts, error cases
│   ├── test_services.py # Unit tests for service dictionary lookups
│   └── test_scanner.py  # Mock live socket tests, banner grabbing, and latency checks
├── scan.py              # CLI executable entry point
├── scan_report.json     # Sample scan output artifact
└── requirements.txt     # Dependency definition (Zero external dependencies)
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher (`py` or `python` command)

### Installation
Clone or navigate to the project directory:
```bash
cd tcp-port-scanner
```

### Running Scans

#### 1. Scan Top 20 Most Common Ports with Banner Grabbing
```bash
py scan.py scanme.nmap.org --top 20 -b
```

#### 2. Scan a Specific Port Range with 150 Threads
```bash
py scan.py 192.168.1.1 -p 1-1024 -w 150 -t 0.8
```

#### 3. Scan Common Web and Database Ports
```bash
py scan.py localhost -p 22,80,443,3306,5432,6379,8080
```

#### 4. Export Structured JSON and CSV Reports
```bash
py scan.py example.com --top 100 -j audit.json -o audit.csv
```

#### 5. Include Filtered & Closed Ports in Output Table
```bash
py scan.py 127.0.0.1 -p 80-85 -a
```

---

## ⚙️ CLI Reference Options

| Argument | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `target` | - | Target IP address or hostname (`127.0.0.1`, `scanme.nmap.org`) | *Required* |
| `-p` | `--ports` | Port list (`80,443`), range (`1-500`), or preset (`top20`, `top100`, `common`, `all`) | `1-1024` |
| | `--top` | Shortcut to scan top common ports (`20` or `100`) | None |
| `-w` | `--threads` | Number of concurrent worker threads | `100` |
| `-t` | `--timeout` | Socket connection timeout in seconds | `1.0` |
| `-b` | `--banner` | Enable service banner grabbing and version fingerprinting | `False` |
| `-a` | `--all` | Show all ports (including closed/filtered) in table | `False` |
| `-j` | `--json` | Export audit results to a JSON file | None |
| `-o` | `--output` | Export report to plain text (`.txt`) or CSV (`.csv`) | None |
| | `--no-color` | Disable ANSI color sequences in console output | `False` |
| `-q` | `--quiet` | Suppress banner and progress bar; output only final results | `False` |

---

## 🧪 Automated Testing

The project includes automated unit and functional tests covering port parsing, service lookups, mock server socket handshakes, and banner extraction.

Run the test suite with Python's built-in `unittest`:
```bash
py -m unittest discover tests
```

Expected output:
```
.......................
----------------------------------------------------------------------
Ran 23 tests in 1.226s

OK
```

---

## 💼 Resume Bullet Points

Enhance your resume by using these metric-driven, impact-oriented bullet points tailored for software engineering and cybersecurity roles:

### Option A: Impact & Performance Focused (Recommended)
> - **Engineered a multi-threaded TCP network reconnaissance tool in Python** utilizing low-level socket programming and `ThreadPoolExecutor`, reducing scan times across 1,000+ ports from minutes to under 5 seconds.
> - **Architected active banner grabbing and service fingerprinting mechanisms** to identify exposed web, SSH, and database software versions, outputting structured JSON/CSV security reports for audit automation.
> - **Implemented robust protocol state handling** to distinguish between open (SYN-ACK), closed (RST), and firewall-filtered (silent drop) ports across varied network topologies.

### Option B: Systems & Networking Fundamentals Focused
> - **Developed an asynchronous TCP port scanner using Python BSD sockets**, executing full three-way handshakes to detect exposed attack surfaces on target hosts.
> - **Integrated protocol-specific probes (HTTP, SSH, FTP, Redis)** to inspect response headers and banners, achieving automated service identification without external dependencies.
> - **Designed a modular CLI suite with comprehensive unit testing (23 test cases)**, incorporating real-time concurrency controls, custom timeouts, and thread-safe progress reporting.

---

## 🎓 Technical Interview Talking Points & Deep-Dive FAQ

When interviewers ask about this project, use the following technical explanations to demonstrate deep understanding:

### 1. TCP Connect Scan vs. SYN Stealth Scan
- **TCP Connect Scan (Used in this tool)**: Completes the full TCP 3-way handshake (`SYN` -> `SYN-ACK` -> `ACK`). It works entirely in standard user space using portable BSD socket APIs (`socket.connect`), requiring **no root/administrator privileges**. The trade-off is that it is easily logged by target firewalls and application connection logs.
- **SYN Stealth Scan (Half-Open)**: Sends a `SYN` packet and waits for `SYN-ACK`, but responds with `RST` before completing the handshake. This prevents application-level connection logging, but requires **raw socket privileges** (`SOCK_RAW`) and OS administrator/root rights.

### 2. Concurrency: Why ThreadPoolExecutor vs. Asyncio?
- Socket connect operations are **I/O-bound**, meaning threads spend most of their time waiting for OS network ACKs rather than consuming CPU.
- While Python has a Global Interpreter Lock (GIL), the C socket implementation **releases the GIL** during blocking OS calls (`connect()`, `recv()`). Thus, multiple threads execute network I/O truly concurrently.
- `ThreadPoolExecutor` provides fine-grained pool sizing, natural exception isolation per port, and zero requirement for third-party event loops.

### 3. Differentiating Open vs. Closed vs. Filtered Ports
- **OPEN**: Target system TCP stack sends `SYN-ACK` (connection succeeds, returncode 0).
- **CLOSED**: Target system is reachable, but no application is listening on that port. The target OS kernel returns a TCP `RST, ACK` packet immediately (`ECONNREFUSED` / `WinError 10061`).
- **FILTERED**: A network firewall, security group, or OS packet filter (like Windows Filtering Platform or iptables) silently drops incoming `SYN` packets without sending an `RST`. This causes the client socket to exceed its configured timeout (`ETIMEDOUT` / `WinError 10060`).

### 4. What is Banner Grabbing and Why is it Critical?
- Identifying that port 80 is open only reveals that an HTTP service is running.
- **Banner Grabbing** actively inspects the application layer greeting (e.g., `Apache/2.4.7 (Ubuntu)` or `SSH-2.0-OpenSSH_6.6.1p1`). This enables security analysts to cross-reference specific software versions against Known Exploits and Common Vulnerabilities and Exposures (CVEs).
