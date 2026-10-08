"""
Web GUI for TCP Port Scanner.
Runs a local HTTP server on http://localhost:5000 with a dark-mode cybersecurity dashboard.
Powered 100% by Python Standard Library (no Flask/Django needed).
"""

import json
import os
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Ensure scanner package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.core import PortScanner
from scanner.parser import (
    InvalidPortSpecificationError,
    TargetResolutionError,
    parse_ports,
    resolve_target,
)

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetPulse | TCP Port Scanner</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --card-border: #1f2937;
      --primary: #06b6d4;
      --primary-hover: #0891b2;
      --accent: #10b981;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --danger: #ef4444;
      --warning: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background-color: var(--bg); color: var(--text); min-height: 100vh; padding: 2rem 1rem; }
    .container { max-width: 1100px; margin: 0 auto; }
    
    /* Header */
    .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; border-bottom: 1px solid var(--card-border); padding-bottom: 1.5rem; }
    .logo-group { display: flex; align-items: center; gap: 0.8rem; }
    .logo-icon { width: 40px; height: 40px; background: linear-gradient(135deg, #06b6d4, #3b82f6); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 1.3rem; color: #fff; box-shadow: 0 0 15px rgba(6, 182, 212, 0.4); }
    .title { font-size: 1.5rem; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
    .subtitle { font-size: 0.85rem; color: var(--text-muted); }
    .status-badge { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; background: #064e3b; color: #34d399; padding: 0.35rem 0.8rem; border-radius: 9999px; border: 1px solid #059669; }
    .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: #34d399; animation: pulse 2s infinite; }
    @keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(1.2); } 100% { opacity: 1; transform: scale(1); } }

    /* Grid Layout */
    .grid { display: grid; grid-template-columns: 360px 1fr; gap: 1.5rem; }
    @media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }

    /* Card */
    .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3); }
    .card-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 1.2rem; display: flex; align-items: center; gap: 8px; color: #fff; }

    /* Form Controls */
    .form-group { margin-bottom: 1.2rem; }
    .form-label { display: block; font-size: 0.85rem; font-weight: 500; color: var(--text-muted); margin-bottom: 0.4rem; }
    .form-input { width: 100%; background: #1f2937; border: 1px solid #374151; color: #fff; padding: 0.65rem 0.85rem; border-radius: 8px; font-size: 0.9rem; transition: border 0.2s; }
    .form-input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.2); }
    
    .quick-targets { display: flex; gap: 6px; margin-top: 0.4rem; }
    .quick-btn { background: #1e293b; border: 1px solid #334155; color: #94a3b8; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s; }
    .quick-btn:hover { background: #334155; color: #fff; border-color: var(--primary); }

    .preset-pills { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 0.4rem; }
    .preset-pill { background: #1e293b; border: 1px solid #334155; color: #cbd5e1; padding: 6px 10px; border-radius: 6px; font-size: 0.8rem; cursor: pointer; text-align: center; transition: all 0.2s; }
    .preset-pill.active { background: rgba(6, 182, 212, 0.15); border-color: var(--primary); color: var(--primary); font-weight: 600; }

    .range-flex { display: flex; align-items: center; gap: 10px; }
    .range-value { font-size: 0.85rem; color: var(--primary); font-weight: 600; min-width: 45px; text-align: right; }

    .checkbox-group { display: flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; margin-top: 0.5rem; }
    .checkbox-group input { accent-color: var(--primary); width: 16px; height: 16px; }
    .checkbox-label { font-size: 0.85rem; color: #cbd5e1; }

    .scan-btn { width: 100%; background: linear-gradient(135deg, #06b6d4, #2563eb); color: #fff; border: none; padding: 0.85rem; border-radius: 8px; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: all 0.3s; display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 1.5rem; box-shadow: 0 4px 15px rgba(6, 182, 212, 0.3); }
    .scan-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(6, 182, 212, 0.4); }
    .scan-btn:disabled { opacity: 0.6; cursor: not-allowed; }

    /* Metrics Bar */
    .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
    @media (max-width: 600px) { .metrics-grid { grid-template-columns: repeat(2, 1fr); } }
    .metric-card { background: #111827; border: 1px solid var(--card-border); border-radius: 10px; padding: 1rem; text-align: center; }
    .metric-num { font-size: 1.5rem; font-weight: 700; color: #fff; margin-bottom: 0.2rem; }
    .metric-num.open { color: var(--accent); }
    .metric-num.filtered { color: var(--warning); }
    .metric-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }

    /* Progress Bar */
    .progress-wrapper { margin-bottom: 1.5rem; display: none; }
    .progress-text { display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem; }
    .progress-track { width: 100%; height: 8px; background: #1f2937; border-radius: 999px; overflow: hidden; }
    .progress-fill { height: 100%; width: 0%; background: linear-gradient(90deg, #06b6d4, #10b981); transition: width 0.2s; }

    /* Results Table */
    .table-container { overflow-x: auto; max-height: 480px; overflow-y: auto; border: 1px solid var(--card-border); border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
    th { background: #1f2937; color: #9ca3af; padding: 0.75rem 1rem; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; position: sticky; top: 0; }
    td { padding: 0.75rem 1rem; border-top: 1px solid #1f2937; color: #e5e7eb; }
    tr:hover { background: #1e293b; }

    .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .badge.open { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #059669; }
    .badge.closed { background: rgba(107, 114, 128, 0.2); color: #9ca3af; border: 1px solid #4b5563; }
    .badge.filtered { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #d97706; }

    .banner-text { font-family: monospace; font-size: 0.8rem; color: #38bdf8; word-break: break-all; }
    .empty-state { text-align: center; padding: 3rem 1rem; color: var(--text-muted); }
    .export-btns { display: flex; gap: 8px; margin-top: 1rem; justify-content: flex-end; }
    .export-btn { background: #1f2937; border: 1px solid #374151; color: #e5e7eb; padding: 0.4rem 0.8rem; border-radius: 6px; font-size: 0.8rem; cursor: pointer; transition: all 0.2s; }
    .export-btn:hover { background: #374151; border-color: var(--primary); }

    .spinner { border: 2px solid rgba(255, 255, 255, 0.3); border-top: 2px solid #fff; border-radius: 50%; width: 14px; height: 14px; animation: spin 0.8s linear infinite; display: inline-block; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="header">
      <div class="logo-group">
        <div class="logo-icon">&#9889;</div>
        <div>
          <h1 class="title">NetPulse Scanner</h1>
          <p class="subtitle">Multi-Threaded TCP Reconnaissance & Service Fingerprinting</p>
        </div>
      </div>
      <div class="status-badge">
        <div class="pulse-dot"></div>
        <span>Engine Online</span>
      </div>
    </header>

    <!-- Main Grid -->
    <div class="grid">
      <!-- Control Panel -->
      <div class="card">
        <h2 class="card-title">&#9881;&#65039; Scan Parameters</h2>
        <form id="scanForm">
          <div class="form-group">
            <label class="form-label" for="target">Target Host / IP</label>
            <input type="text" id="target" class="form-input" value="127.0.0.1" required placeholder="e.g. 127.0.0.1 or scanme.nmap.org" />
            <div class="quick-targets">
              <span class="quick-btn" onclick="setTarget('127.0.0.1')">Localhost</span>
              <span class="quick-btn" onclick="setTarget('scanme.nmap.org')">scanme.nmap.org</span>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">Port Profile</label>
            <div class="preset-pills">
              <div class="preset-pill active" onclick="setPreset('top20', this)">Top 20 Ports</div>
              <div class="preset-pill" onclick="setPreset('top100', this)">Top 100 Ports</div>
              <div class="preset-pill" onclick="setPreset('common', this)">Common (1-1024)</div>
              <div class="preset-pill" onclick="setPreset('custom', this)">Custom Ports</div>
            </div>
          </div>

          <div class="form-group" id="customPortGroup" style="display: none;">
            <label class="form-label" for="customPorts">Custom Ports</label>
            <input type="text" id="customPorts" class="form-input" placeholder="e.g. 21,22,80,443,3306,8080 or 80-90" />
          </div>

          <div class="form-group">
            <label class="form-label" for="threads">Concurrency (Worker Threads)</label>
            <div class="range-flex">
              <input type="range" id="threads" min="10" max="250" value="75" style="width: 100%; accent-color: var(--primary);" oninput="document.getElementById('threadVal').innerText = this.value" />
              <span class="range-value" id="threadVal">75</span>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label" for="timeout">Socket Timeout (Seconds)</label>
            <div class="range-flex">
              <input type="range" id="timeout" min="0.2" max="3.0" step="0.1" value="1.0" style="width: 100%; accent-color: var(--primary);" oninput="document.getElementById('timeoutVal').innerText = this.value + 's'" />
              <span class="range-value" id="timeoutVal">1.0s</span>
            </div>
          </div>

          <div class="form-group">
            <label class="checkbox-group">
              <input type="checkbox" id="bannerGrab" checked />
              <span class="checkbox-label">Active Banner Grabbing (Fingerprinting)</span>
            </label>
            <label class="checkbox-group">
              <input type="checkbox" id="showAll" />
              <span class="checkbox-label">Display closed & filtered ports in table</span>
            </label>
          </div>

          <button type="submit" id="submitBtn" class="scan-btn">
            <span id="btnText">&#9654; Launch Port Scan</span>
          </button>
        </form>
      </div>

      <!-- Right Column: Results & Metrics -->
      <div>
        <!-- Metrics Cards -->
        <div class="metrics-grid">
          <div class="metric-card">
            <div class="metric-num" id="totalScanned">0</div>
            <div class="metric-label">Ports Scanned</div>
          </div>
          <div class="metric-card">
            <div class="metric-num open" id="openCount">0</div>
            <div class="metric-label">Open Ports</div>
          </div>
          <div class="metric-card">
            <div class="metric-num filtered" id="filteredCount">0</div>
            <div class="metric-label">Filtered / Closed</div>
          </div>
          <div class="metric-card">
            <div class="metric-num" id="scanDuration">0.0s</div>
            <div class="metric-label">Scan Time</div>
          </div>
        </div>

        <!-- Progress Indicator -->
        <div class="progress-wrapper" id="progressWrapper">
          <div class="progress-text">
            <span id="progressStatus">Auditing ports...</span>
            <span id="progressPct">0%</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill" id="progressFill"></div>
          </div>
        </div>

        <!-- Table Card -->
        <div class="card" style="padding: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.8rem;">
            <h3 style="font-size: 1rem; color: #fff;">Discovered Ports & Services</h3>
            <span id="targetMeta" style="font-size: 0.8rem; color: var(--text-muted); font-family: monospace;"></span>
          </div>

          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Port</th>
                  <th>State</th>
                  <th>Service</th>
                  <th>Latency</th>
                  <th>Banner / Version</th>
                </tr>
              </thead>
              <tbody id="resultsBody">
                <tr>
                  <td colspan="5" class="empty-state">
                    Enter a target host and click "Launch Port Scan" to begin.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="export-btns">
            <button class="export-btn" onclick="exportData('json')">&#128190; Export JSON</button>
            <button class="export-btn" onclick="exportData('csv')">&#128196; Export CSV</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    let currentPreset = 'top20';
    let lastScanData = null;

    function setTarget(val) {
      document.getElementById('target').value = val;
    }

    function setPreset(preset, el) {
      currentPreset = preset;
      document.querySelectorAll('.preset-pill').forEach(p => p.classList.remove('active'));
      el.classList.add('active');
      const customGroup = document.getElementById('customPortGroup');
      if (preset === 'custom') {
        customGroup.style.display = 'block';
      } else {
        customGroup.style.display = 'none';
      }
    }

    document.getElementById('scanForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      const target = document.getElementById('target').value.trim();
      const threads = parseInt(document.getElementById('threads').value);
      const timeout = parseFloat(document.getElementById('timeout').value);
      const banner = document.getElementById('bannerGrab').checked;
      const showAll = document.getElementById('showAll').checked;
      const customPorts = document.getElementById('customPorts').value.trim();

      const submitBtn = document.getElementById('submitBtn');
      const btnText = document.getElementById('btnText');
      const progressWrapper = document.getElementById('progressWrapper');
      const progressFill = document.getElementById('progressFill');

      submitBtn.disabled = true;
      btnText.innerHTML = '<span class="spinner"></span> Scanning...';
      progressWrapper.style.display = 'block';
      progressFill.style.width = '30%';

      try {
        const payload = {
          target: target,
          preset: currentPreset,
          custom_ports: customPorts,
          threads: threads,
          timeout: timeout,
          banner: banner,
          show_all: showAll
        };

        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        progressFill.style.width = '90%';
        const data = await res.json();
        progressFill.style.width = '100%';

        if (data.error) {
          alert('Scan Error: ' + data.error);
          return;
        }

        lastScanData = data;
        renderResults(data, showAll);
      } catch (err) {
        alert('Network or server error: ' + err.message);
      } finally {
        submitBtn.disabled = false;
        btnText.innerHTML = '&#9654; Launch Port Scan';
        setTimeout(() => { progressWrapper.style.display = 'none'; }, 600);
      }
    });

    function renderResults(data, showAll) {
      document.getElementById('totalScanned').innerText = data.metrics.total_ports;
      document.getElementById('openCount').innerText = data.metrics.open_count;
      document.getElementById('filteredCount').innerText = data.metrics.filtered_count + data.metrics.closed_count;
      document.getElementById('scanDuration').innerText = data.metrics.duration_seconds + 's';
      document.getElementById('targetMeta').innerText = `${data.target.host} (${data.target.ip})`;

      const tbody = document.getElementById('resultsBody');
      tbody.innerHTML = '';

      const items = showAll ? data.results : data.results.filter(r => r.state === 'OPEN');

      if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">&#9888;&#65039; No ${showAll ? '' : 'open '}ports detected in the selected range.</td></tr>`;
        return;
      }

      items.forEach(r => {
        const tr = document.createElement('tr');
        const badgeClass = r.state.toLowerCase();
        tr.innerHTML = `
          <td><strong>${r.port}</strong>/tcp</td>
          <td><span class="badge ${badgeClass}">${r.state}</span></td>
          <td>${r.service}</td>
          <td>${r.latency_ms} ms</td>
          <td><span class="banner-text">${r.banner || '-'}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }

    function exportData(type) {
      if (!lastScanData) {
        alert('Run a scan before exporting.');
        return;
      }
      if (type === 'json') {
        const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `port_scan_${lastScanData.target.ip}.json`;
        a.click();
      } else if (type === 'csv') {
        let csv = 'Port,Protocol,State,Service,Latency_ms,Banner\\n';
        lastScanData.results.forEach(r => {
          csv += `"${r.port}","tcp","${r.state}","${r.service}","${r.latency_ms}","${(r.banner || '').replace(/"/g, '""')}"\\n`;
        });
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `port_scan_${lastScanData.target.ip}.csv`;
        a.click();
      }
    }
  </script>
</body>
</html>
"""


class ScannerHTTPHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for web UI and scan API."""

    def log_message(self, format, *args):
        # Clean log format
        sys.stdout.write(f"[Web GUI] {self.address_string()} - {format % args}\n")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        elif parsed.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "running"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)

            try:
                body = json.loads(body_bytes.decode("utf-8"))
                target = body.get("target", "127.0.0.1")
                preset = body.get("preset", "top20")
                custom_ports = body.get("custom_ports", "")
                threads = int(body.get("threads", 75))
                timeout = float(body.get("timeout", 1.0))
                banner = bool(body.get("banner", True))

                # Step 1: Target resolution
                target_ip, target_host = resolve_target(target)

                # Step 2: Port parsing
                if preset == "top20":
                    ports = parse_ports("top20")
                elif preset == "top100":
                    ports = parse_ports("top100")
                elif preset == "common":
                    ports = parse_ports("common")
                elif preset == "custom":
                    ports = parse_ports(custom_ports if custom_ports else "top20")
                else:
                    ports = parse_ports("top20")

                # Step 3: Run scan
                scanner = PortScanner(
                    target_ip=target_ip,
                    target_host=target_host,
                    ports=ports,
                    timeout=timeout,
                    max_threads=threads,
                    grab_banners=banner,
                )
                summary = scanner.run()

                # Step 4: Serialize response
                response_data = {
                    "target": {
                        "host": summary.target_host,
                        "ip": summary.target_ip,
                    },
                    "metrics": {
                        "total_ports": summary.total_ports,
                        "open_count": summary.open_count,
                        "closed_count": summary.closed_count,
                        "filtered_count": summary.filtered_count,
                        "duration_seconds": round(summary.duration_seconds, 2),
                    },
                    "results": [
                        {
                            "port": r.port,
                            "protocol": "tcp",
                            "state": r.state,
                            "service": r.service,
                            "latency_ms": r.latency_ms,
                            "banner": r.banner,
                        }
                        for r in summary.results
                    ],
                }

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode("utf-8"))

            except (TargetResolutionError, InvalidPortSpecificationError) as err:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(err)}).encode("utf-8"))
            except Exception as err:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Internal scan error: {str(err)}"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def start_server(port: int = 5000, open_browser: bool = True):
    """Start local web dashboard server."""
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, ScannerHTTPHandler)
    url = f"http://localhost:{port}"

    print("=" * 64)
    print("  NETPULSE TCP PORT SCANNER - WEB DASHBOARD")
    print(f"  Server URL:  {url}")
    print("  Status:      Running on localhost")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 64)

    if open_browser:
        threading.Thread(
            target=lambda: (time.sleep(0.6), webbrowser.open(url)),
            daemon=True,
        ).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down web dashboard server.")
        httpd.shutdown()


if __name__ == "__main__":
    start_server(port=5000, open_browser=True)
