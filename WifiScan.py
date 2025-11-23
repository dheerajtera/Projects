#!/usr/bin/env python3
# File: tools/wifi_audit.py
"""
WiFi Audit Tool (CLI + optional Web UI)
- Passive scanning of Wi-Fi beacons/probe responses.
- Optional safe active probing (directed probe requests) ONLY when --consent provided.
- Detection: open/WEP/WPA1, duplicate SSIDs, hidden SSIDs, RSSI anomalies.
- Export: JSON and PDF.
- Optional Flask dashboard to view history.
Requirements: root (for monitor-mode capture), Python 3.8+, install:
    pip install scapy==2.4.5 flask reportlab pandas
Notes:
- This tool intentionally avoids disruptive actions (no deauth).
- Works best on Linux with interface in monitor mode (e.g., wlan0mon).
"""

import argparse
import json
import os
import sys
import time
import threading
from datetime import datetime
from collections import defaultdict, deque

# Minimal external libs; import lazily to provide helpful error messages.
try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11ProbeReq, sendp, Dot11EltRSN
except Exception as e:
    print("scapy import error:", e)
    print("Install scapy (pip install scapy) and run with root on a machine that supports monitor mode.")
    # We'll still allow non-capture functions like report export to run.
    sniff = None
    Dot11 = Dot11Beacon = Dot11Elt = None

try:
    from flask import Flask, jsonify, render_template_string, request
except Exception:
    Flask = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except Exception:
    canvas = None

import math
import socket

HOME = os.path.expanduser("~")
HISTORY_DIR = os.path.join(HOME, ".wifi_audit")
HISTORY_FILE = os.path.join(HISTORY_DIR, "history.jsonl")
DEFAULT_SCAN_SECONDS = 20

# Helpers --------------------------------------------------------------------

def ensure_history_dir():
    os.makedirs(HISTORY_DIR, exist_ok=True)

def save_history_snapshot(snapshot: dict):
    ensure_history_dir()
    with open(HISTORY_FILE, "a") as f:
        f.write(json.dumps(snapshot) + "\n")

def load_history(n=100):
    if not os.path.exists(HISTORY_FILE):
        return []
    lines = deque([], maxlen=n)
    with open(HISTORY_FILE, "r") as f:
        for line in f:
            try:
                lines.append(json.loads(line))
            except Exception:
                continue
    return list(lines)

def mac_to_oui(mac: str):
    # Simple OUI formatting
    return mac.upper()[0:8] if mac and len(mac) >= 8 else None

# Frame parsing utilities ---------------------------------------------------

def parse_security(pkt):
    # Returns human string: "Open", "WEP", "WPA1", "WPA2/WPA3(RSN)"
    # pkt is Dot11Beacon or Dot11ProbeResp scapy pkt
    if pkt is None:
        return "Unknown"
    # Check capability field for privacy (WEP) and RSN/WPA elements
    try:
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
    except Exception:
        cap = None
    # Find elements
    ssid = None
    rsn_found = False
    wpa_found = False
    privacy = False
    wep = False
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        ID = elt.ID
        info = elt.info if hasattr(elt, "info") else b""
        if ID == 0:
            ssid = info.decode(errors="ignore")
        elif ID == 48:
            rsn_found = True
        elif ID == 221 and info.startswith(b"\x00P\xf2\x01"):  # WPA IE OUI
            wpa_found = True
        elt = elt.payload.getlayer(Dot11Elt)
    # privacy bit via capabilities - quick heuristic
    try:
        if pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").find("privacy") != -1:
            privacy = True
    except Exception:
        pass
    if not privacy:
        return "Open"
    # Distinguish WEP vs WPA/WPA2
    if rsn_found or wpa_found:
        # If RSN present, likely WPA2/RSN (could be WPA3 if RSN with AKM selectors later)
        return "WPA2/RSN"
    # privacy but no RSN/WPA -> likely WEP or WPA1
    # Check common WEP usage heuristics: older networks with privacy bit and no RSN.
    return "WEP or WPA1 (deprecated)"

def extract_ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:
            return elt.info.decode(errors="ignore")
        elt = elt.payload.getlayer(Dot11Elt)
    return ""

def extract_channel(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 3:
            # DS Parameter Set
            try:
                return int.from_bytes(elt.info, "little")
            except Exception:
                try:
                    return int(elt.info[0])
                except Exception:
                    return None
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def extract_rssi(pkt):
    # Scapy RadioTap may have dBm_AntSignal
    try:
        return int(pkt.dBm_AntSignal)
    except Exception:
        # Fallback: no RSSI known
        return None

# Scanner class --------------------------------------------------------------

class PassiveScanner:
    def __init__(self, iface, timeout=DEFAULT_SCAN_SECONDS, active_probe=False, consent=False):
        self.iface = iface
        self.timeout = timeout
        self.active_probe = active_probe and consent
        self.consent = consent
        self._stop_event = threading.Event()
        self.lock = threading.Lock()
        # Data: bssid -> info
        self.networks = {}
        # Temporary capture for EAPOL frames (handshake fragments)
        self.eapol_frames = []

    def _handle_pkt(self, pkt):
        # Only handle management frames
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt.addr3
            ssid = extract_ssid(pkt)
            rssi = extract_rssi(pkt)
            channel = extract_channel(pkt)
            security = parse_security(pkt)
            ts = time.time()
            with self.lock:
                entry = self.networks.get(bssid, {
                    "bssid": bssid,
                    "ssid": ssid,
                    "first_seen": ts,
                    "last_seen": ts,
                    "rssi_samples": [],
                    "channel": channel,
                    "security": security,
                    "seen_count": 0,
                })
                entry["ssid"] = ssid or entry.get("ssid", "")
                entry["last_seen"] = ts
                if rssi is not None:
                    entry["rssi_samples"].append({"ts": ts, "rssi": rssi})
                    entry["rssi"] = rssi
                entry["channel"] = channel or entry.get("channel")
                entry["security"] = security or entry.get("security")
                entry["seen_count"] = entry.get("seen_count", 0) + 1
                self.networks[bssid] = entry
        # Passive capture of EAPOL (handshake) frames if present; do not force clients.
        # EAPOL manifests as type/subtype Data with specific EtherType
        if pkt.haslayer("EAPOL") or (pkt.haslayer("Dot11") and b"\x88\x8e" in bytes(pkt)):
            # Record minimal info of witnessed EAPOL frame
            try:
                rec = {
                    "ts": time.time(),
                    "summary": pkt.summary(),
                    "bssid": getattr(pkt, "addr3", None),
                    "from_ds": getattr(pkt, "FCfield", None),
                }
                with self.lock:
                    self.eapol_frames.append(rec)
            except Exception:
                pass

    def _active_probe_worker(self):
        # Send a few directed probe requests for SSIDs seen (non-disruptive)
        # Only if consent provided and scapy sendp available.
        if not self.consent:
            return
        if Dot11 is None:
            return
        # Choose a few sample SSIDs to probe (including broadcast)
        ssids = [""]  # broadcast probe
        with self.lock:
            for v in list(self.networks.values())[:5]:
                if v.get("ssid"):
                    ssids.append(v["ssid"])
        # Build and send probe requests (non-blocking)
        for ssid in ssids:
            # Construct 802.11 Probe Request
            dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=get_local_mac(self.iface) or "00:00:00:00:00:00", addr3="ff:ff:ff:ff:ff:ff")
            probe = RadioTap()/dot11/Dot11ProbeReq()/Dot11Elt(ID=0, info=ssid.encode() if ssid else b"")
            try:
                sendp(probe, iface=self.iface, verbose=False, count=3)
            except Exception:
                pass
            time.sleep(0.2)

    def scan(self):
        if sniff is None:
            raise RuntimeError("scapy not available; cannot perform live scan.")
        # Kick off active probe thread if consented
        if self.active_probe:
            t = threading.Thread(target=self._active_probe_worker, daemon=True)
            t.start()
        # Sniff for beacons/probe responses
        try:
            sniff(iface=self.iface, prn=self._handle_pkt, timeout=self.timeout, store=0)
        except Exception as e:
            raise RuntimeError(f"sniff failed: {e}")
        # Snapshot
        with self.lock:
            data = {
                "timestamp": time.time(),
                "iface": self.iface,
                "networks": list(self.networks.values()),
                "eapol_frames": list(self.eapol_frames),
            }
        # Save to history
        save_history_snapshot(data)
        return data

# Analyzer -------------------------------------------------------------------

class Analyzer:
    def __init__(self, snapshot, history=None, whitelist_bssids=None):
        self.snapshot = snapshot
        self.history = history or []
        self.whitelist_bssids = set(whitelist_bssids or [])
        self.issues = []

    def detect_weak_security(self):
        for n in self.snapshot.get("networks", []):
            sec = n.get("security", "Unknown")
            if sec.startswith("WEP") or "WEP" in sec or "WPA1" in sec or "deprecated" in sec:
                self.issues.append({
                    "type": "weak_security",
                    "bssid": n.get("bssid"),
                    "ssid": n.get("ssid"),
                    "security": sec,
                    "severity": "high",
                    "msg": f"Network {n.get('ssid')} ({n.get('bssid')}) uses weak or deprecated security: {sec}."
                })
            elif sec == "Open":
                self.issues.append({
                    "type": "open_network",
                    "bssid": n.get("bssid"),
                    "ssid": n.get("ssid"),
                    "severity": "medium",
                    "msg": f"Open (unencrypted) network detected: {n.get('ssid')} ({n.get('bssid')})."
                })

    def detect_duplicate_ssids(self):
        ssid_map = defaultdict(list)
        for n in self.snapshot.get("networks", []):
            ssid_map[n.get("ssid", "")].append(n)
        for ssid, entries in ssid_map.items():
            if not ssid:
                # hidden SSIDs
                for e in entries:
                    self.issues.append({
                        "type": "hidden_ssid",
                        "bssid": e.get("bssid"),
                        "ssid": "",
                        "severity": "low",
                        "msg": f"Hidden SSID broadcast (empty SSID) by BSSID {e.get('bssid')}."
                    })
            if len(entries) > 1:
                bssids = [e["bssid"] for e in entries]
                self.issues.append({
                    "type": "duplicate_ssid",
                    "ssid": ssid,
                    "bssids": bssids,
                    "severity": "medium",
                    "msg": f"SSID '{ssid}' advertised by multiple BSSIDs: {', '.join(bssids)}."
                })

    def detect_rogue(self):
        # If whitelist provided, any BSSID announcing a whitelisted SSID but not whitelisted BSSID is suspicious.
        if not self.whitelist_bssids:
            return
        for n in self.snapshot.get("networks", []):
            if n.get("bssid") not in self.whitelist_bssids and self.whitelist_bssids:
                # If SSID matches any known network from history and BSSID new -> suspicious
                seen = False
                for past in self.history:
                    for pnet in past.get("networks", []):
                        if pnet.get("ssid") == n.get("ssid") and pnet.get("bssid") in self.whitelist_bssids:
                            seen = True
                            break
                    if seen: break
                if seen:
                    self.issues.append({
                        "type": "rogue_bssid",
                        "bssid": n.get("bssid"),
                        "ssid": n.get("ssid"),
                        "severity": "high",
                        "msg": f"Potential rogue BSSID {n.get('bssid')} advertising SSID '{n.get('ssid')}' previously seen with other BSSID."
                    })

    def anomaly_rssi(self, threshold_db=15):
        # Compare average RSSI for same BSSID across history; if sudden change > threshold_db, flag.
        for n in self.snapshot.get("networks", []):
            bssid = n.get("bssid")
            curr_rssi = n.get("rssi") if n.get("rssi") is not None else None
            if curr_rssi is None:
                continue
            # compute historical avg rssi for this bssid
            hist_vals = []
            for past in self.history:
                for p in past.get("networks", []):
                    if p.get("bssid") == bssid and p.get("rssi") is not None:
                        hist_vals.append(p.get("rssi"))
            if not hist_vals:
                continue
            avg_hist = sum(hist_vals) / len(hist_vals)
            if abs(curr_rssi - avg_hist) >= threshold_db:
                self.issues.append({
                    "type": "rssi_anomaly",
                    "bssid": bssid,
                    "ssid": n.get("ssid"),
                    "severity": "low",
                    "msg": f"RSSI for {bssid} changed from avg {avg_hist:.1f} dBm to {curr_rssi} dBm (Δ={curr_rssi-avg_hist:.1f} dB)."
                })

    def eapol_observed(self):
        if self.snapshot.get("eapol_frames"):
            self.issues.append({
                "type": "eapol_seen",
                "severity": "info",
                "count": len(self.snapshot.get("eapol_frames")),
                "msg": f"EAPOL handshake frames observed passively ({len(self.snapshot.get('eapol_frames'))} frames). If you intend to capture full WPA handshakes, ensure explicit consent and legal authorization."
            })

    def run_all(self):
        self.detect_weak_security()
        self.detect_duplicate_ssids()
        self.detect_rogue()
        self.anomaly_rssi()
        self.eapol_observed()
        # High-level summary
        sev_map = {"high": 3, "medium": 2, "low": 1, "info": 0}
        severity_score = 0
        for i in self.issues:
            severity_score = max(severity_score, sev_map.get(i.get("severity", "info"), 0))
        summary_level = {0: "Clean", 1: "Low", 2: "Medium", 3: "High"}.get(severity_score, "Unknown")
        return {"summary": summary_level, "issues": self.issues}

# Reporting ------------------------------------------------------------------

def export_json(snapshot, analysis, outpath):
    out = {
        "snapshot": snapshot,
        "analysis": analysis,
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2)
    return outpath

def export_pdf(snapshot, analysis, outpath):
    if canvas is None:
        raise RuntimeError("reportlab not installed; cannot create PDF.")
    c = canvas.Canvas(outpath, pagesize=letter)
    width, height = letter
    margin = 40
    y = height - margin
    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, y, "WiFi Audit Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(margin, y, f"Generated: {datetime.utcnow().isoformat()} UTC")
    y -= 25
    # Summary
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, f"High-level summary: {analysis.get('summary')}")
    y -= 18
    c.setFont("Helvetica", 9)
    for issue in analysis.get("issues", [])[:20]:
        if y < margin + 60:
            c.showPage()
            y = height - margin
        c.drawString(margin, y, f"- [{issue.get('severity').upper()}] {issue.get('msg')}")
        y -= 12
    # Add short table of networks
    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Detected networks (sample):")
    y -= 14
    c.setFont("Helvetica", 9)
    for n in snapshot.get("networks", [])[:40]:
        if y < margin + 40:
            c.showPage()
            y = height - margin
        line = f"{n.get('ssid') or '<hidden>'} | {n.get('bssid')} | ch:{n.get('channel')} | rssi:{n.get('rssi')} | {n.get('security')}"
        c.drawString(margin, y, line)
        y -= 11
    c.save()
    return outpath

# Utility to get MAC of local iface; best-effort fallback
def get_local_mac(iface):
    try:
        import fcntl, struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15].encode()))
        mac = ''.join('%02x:' % b for b in info[18:24])[:-1]
        return mac
    except Exception:
        return None

# Simple CLI and Flask dashboard --------------------------------------------

FLASK_TEMPLATE = """
<!doctype html>
<title>WiFi Audit Dashboard</title>
<h2>WiFi Audit — Recent Scans</h2>
<p>Latest {{count}} snapshots (newest first)</p>
<table border=1 cellpadding=4>
<thead><tr><th>Time (UTC)</th><th>Interface</th><th>#Networks</th><th>Summary</th></tr></thead>
<tbody>
{% for s in snaps %}
<tr>
<td>{{s.generated_at}}</td>
<td>{{s.snapshot.iface}}</td>
<td>{{s.snapshot.networks|length}}</td>
<td>{{s.analysis.summary}}</td>
</tr>
{% endfor %}
</tbody>
</table>
"""

def run_flask(port=5000):
    if Flask is None:
        raise RuntimeError("Flask not installed. pip install flask")
    app = Flask(__name__)
    @app.route("/")
    def index():
        snaps = load_history(50)
        combined = []
        for s in reversed(snaps):
            # Run quick analysis for display
            a = Analyzer(s, history=snaps).run_all()
            combined.append({"snapshot": s, "analysis": a, "generated_at": datetime.utcfromtimestamp(s["timestamp"]).isoformat()})
        return render_template_string(FLASK_TEMPLATE, snaps=combined, count=len(combined))
    app.run(port=port, debug=False)

# CLI entrypoint ------------------------------------------------------------

def require_root_or_exit():
    if os.geteuid() != 0:
        print("This script must be run as root for live packet capture (scapy sniff).")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="WiFi Audit Tool (passive + safe active probing)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Perform passive (and optional safe active) scan")
    p_scan.add_argument("-i", "--iface", required=True, help="Interface in monitor mode (e.g., wlan0mon)")
    p_scan.add_argument("-t", "--time", type=int, default=DEFAULT_SCAN_SECONDS, help="Scan duration seconds")
    p_scan.add_argument("--consent", action="store_true", help="Explicit consent for safe active probing (non-disruptive only)")
    p_scan.add_argument("--whitelist-bssid", nargs="*", default=[], help="Known/whitelisted BSSIDs (optional)")

    p_export = sub.add_parser("export", help="Export last snapshot to JSON/PDF")
    p_export.add_argument("--json", help="Output JSON path")
    p_export.add_argument("--pdf", help="Output PDF path")

    p_serve = sub.add_parser("serve", help="Start web dashboard (view history)")
    p_serve.add_argument("--port", type=int, default=5000)

    p_history = sub.add_parser("history", help="List saved history snapshots (timestamps)")
    p_analyze = sub.add_parser("analyze", help="Analyze last saved snapshot using history")
    p_analyze.add_argument("--whitelist-bssid", nargs="*", default=[], help="Known/whitelisted BSSIDs (optional)")

    args = parser.parse_args()

    if args.cmd == "scan":
        require_root_or_exit()
        if sniff is None:
            print("scapy not available; cannot scan. Install scapy and run again.")
            sys.exit(1)
        if args.consent:
            print("User provided consent for safe active probing.")
        else:
            print("Running passive scan only. Use --consent to allow safe active probing (directed probe requests).")
        scanner = PassiveScanner(args.iface, timeout=args.time, active_probe=True, consent=args.consent)
        try:
            snapshot = scanner.scan()
        except Exception as e:
            print("Scan failed:", e)
            sys.exit(1)
        # Load history (excluding last appended snapshot)
        hist = load_history(200)[:-1] if os.path.exists(HISTORY_FILE) else []
        analyzer = Analyzer(snapshot, history=hist, whitelist_bssids=args.whitelist_bssid)
        analysis = analyzer.run_all()
        # CLI high-level output
        print("\n=== High-level findings ===")
        print(f"Summary level: {analysis.get('summary')}")
        for it in analysis.get("issues", []):
            print(f"- [{it.get('severity')}] {it.get('msg')}")
        print("\nDetected networks (sample):")
        for n in snapshot.get("networks", [])[:20]:
            print(f"{n.get('ssid') or '<hidden>'} | {n.get('bssid')} | ch:{n.get('channel')} | rssi:{n.get('rssi')} | {n.get('security')}")
        print(f"\nSnapshot saved to history ({HISTORY_FILE})")
        # Also write a JSON summary automatically next to history for convenience
        outjson = os.path.join(HISTORY_DIR, f"last_snapshot_{int(time.time())}.json")
        with open(outjson, "w") as f:
            json.dump({"snapshot": snapshot, "analysis": analysis, "generated_at": datetime.utcnow().isoformat()+"Z"}, f, indent=2)
        print("Saved quick export:", outjson)

    elif args.cmd == "export":
        snaps = load_history(1)
        if not snaps:
            print("No history snapshots found. Run a scan first.")
            sys.exit(1)
        snapshot = snaps[-1]
        analyzer = Analyzer(snapshot, history=load_history(200))
        analysis = analyzer.run_all()
        if args.json:
            p = export_json(snapshot, analysis, args.json)
            print("Exported JSON to", p)
        if args.pdf:
            try:
                p = export_pdf(snapshot, analysis, args.pdf)
                print("Exported PDF to", p)
            except Exception as e:
                print("PDF export failed:", e)
        if not args.json and not args.pdf:
            print("No output path specified. Use --json or --pdf.")

    elif args.cmd == "serve":
        print("Starting local web dashboard (read-only) — open http://127.0.0.1:%d" % args.port)
        run_flask(port=args.port)

    elif args.cmd == "history":
        snaps = load_history(200)
        if not snaps:
            print("No history found.")
        else:
            for i, s in enumerate(snaps[-50:]):
                print(f"{i+1:02d}. {datetime.utcfromtimestamp(s['timestamp']).isoformat()} UTC | iface={s.get('iface')} | networks={len(s.get('networks', []))}")

    elif args.cmd == "analyze":
        snaps = load_history(200)
        if not snaps:
            print("No history snapshots found.")
            sys.exit(1)
        snapshot = snaps[-1]
        analyzer = Analyzer(snapshot, history=snaps[:-1], whitelist_bssids=args.whitelist_bssid)
        analysis = analyzer.run_all()
        print("Summary:", analysis.get("summary"))
        for it in analysis.get("issues", []):
            print(f"- [{it.get('severity')}] {it.get('msg')}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
