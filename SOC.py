import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import threading
import queue
import time
import socket
import json
import os
from collections import defaultdict, deque
import random
import subprocess
import platform

# Scapy imports
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, get_if_list, conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---------------- CONFIG ----------------
st.set_page_config(page_title="SOC - Threat Hunting", layout="wide", page_icon="🛡️")

# ---------------- SESSION STATE ----------------
if "packets" not in st.session_state:
    st.session_state.packets = deque(maxlen=10000)
if "alerts" not in st.session_state:
    st.session_state.alerts = deque(maxlen=1000)
if "capture_running" not in st.session_state:
    st.session_state.capture_running = False
if "packet_queue" not in st.session_state:
    st.session_state.packet_queue = queue.Queue()
if "alert_queue" not in st.session_state:
    st.session_state.alert_queue = queue.Queue()
if "stats" not in st.session_state:
    st.session_state.stats = {
        "total": 0,
        "high_alerts": 0,
        "auth_failure": 0,
        "auth_success": 0,
        "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0
    }
if "port_scan_tracker" not in st.session_state:
    st.session_state.port_scan_tracker = defaultdict(set)
if "conn_tracker" not in st.session_state:
    st.session_state.conn_tracker = defaultdict(int)
if "mitre_counts" not in st.session_state:
    st.session_state.mitre_counts = defaultdict(int)
if "agent_counts" not in st.session_state:
    st.session_state.agent_counts = defaultdict(int)
if "capture_thread" not in st.session_state:
    st.session_state.capture_thread = None
if "active_blocks" not in st.session_state:
    st.session_state.active_blocks = deque(maxlen=500)
if "os_detections" not in st.session_state:
    st.session_state.os_detections = {}
if "hping3_attack" not in st.session_state:
    st.session_state.hping3_attack = False
if "hping3_target" not in st.session_state:
    st.session_state.hping3_target = ""
if "hping3_stats" not in st.session_state:
    st.session_state.hping3_stats = {
        "packets_sent": 0,
        "start_time": None,
        "attack_type": "",
        "target": ""
    }
if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = set()
if "timeline_data" not in st.session_state:
    st.session_state.timeline_data = deque(maxlen=1000)

# ---------------- THREAT DETECTION RULES ----------------
SUSPICIOUS_PORTS = {
    23: ("Telnet - Cleartext", "Valid Accounts", 8),
    445: ("SMB - Lateral Movement", "Lateral Movement", 7),
    3389: ("RDP", "Remote Services", 6),
    22: ("SSH", "SSH", 5),
    21: ("FTP - Cleartext", "Brute Force", 7),
    139: ("NetBIOS", "System Info", 6),
    135: ("MSRPC", "System Binary Proxy", 7),
    1433: ("MSSQL", "Password Guessing", 7),
    3306: ("MySQL", "Password Guessing", 7),
    5900: ("VNC", "Remote Services", 8),
    4444: ("Metasploit Default", "C2 Communication", 12),
    31337: ("Backdoor Port", "C2 Communication", 12),
    6667: ("IRC - Possible C2", "C2 Communication", 10),
}

MITRE_TECHNIQUES = {
    "T1046": "Network Service Scanning",
    "T1110": "Brute Force",
    "T1071": "Application Layer Protocol",
    "T1021": "Remote Services",
    "T1078": "Valid Accounts",
    "T1218": "Signed Binary Proxy Execution",
    "T1499": "Endpoint DoS",
    "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing App",
}

# OS Detection signatures based on TTL and other characteristics
OS_TTL_MAP = {
    (64, 64): "Linux/Unix",
    (128, 128): "Windows",
    (255, 255): "Cisco/Network Device",
    (64, 65): "Linux/Unix (Modified)",
    (128, 129): "Windows (Modified)",
    (60, 64): "macOS/iOS",
    (30, 64): "Unknown/VPN",
}


def detect_os(ttl, window_size=None):
    """Detect OS based on TTL and TCP window size"""
    if ttl <= 64:
        if window_size and window_size == 65535:
            return "macOS/iOS"
        return "Linux/Unix"
    elif ttl <= 128:
        if window_size and window_size in [8192, 65535]:
            return "Windows (Modern)"
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Network Device"
    return "Unknown"


def get_os_icon(os_name):
    """Get emoji icon for OS"""
    icons = {
        "Linux/Unix": "🐧",
        "Windows": "🪟",
        "Windows (Modern)": "🪟",
        "macOS/iOS": "🍎",
        "Cisco/Network Device": "🔌",
        "Unknown": "❓",
        "Unknown/VPN": "🔒"
    }
    for key, icon in icons.items():
        if key in os_name:
            return icon
    return "❓"


# ---------------- PACKET PROCESSOR ----------------
def analyze_packet(pkt):
    """Analyze packet, return dict + optional alert."""
    packet_info = {
        "timestamp": datetime.now(),
        "src": "N/A", "dst": "N/A", "sport": 0, "dport": 0,
        "proto": "OTHER", "length": len(pkt), "flags": "",
        "ttl": 0, "os_guess": "Unknown", "window_size": 0
    }
    alert = None

    if IP in pkt:
        packet_info["src"] = pkt[IP].src
        packet_info["dst"] = pkt[IP].dst
        packet_info["ttl"] = pkt[IP].ttl

        if TCP in pkt:
            packet_info["proto"] = "TCP"
            packet_info["sport"] = pkt[TCP].sport
            packet_info["dport"] = pkt[TCP].dport
            packet_info["flags"] = str(pkt[TCP].flags)
            packet_info["window_size"] = pkt[TCP].window

            # OS Detection
            os_guess = detect_os(pkt[IP].ttl, pkt[TCP].window)
            packet_info["os_guess"] = os_guess

            # Store OS detection
            src_ip = pkt[IP].src
            if src_ip not in st.session_state.os_detections:
                st.session_state.os_detections[src_ip] = {
                    "os": os_guess,
                    "ttl": pkt[IP].ttl,
                    "window_size": pkt[TCP].window,
                    "first_seen": datetime.now(),
                    "last_seen": datetime.now(),
                    "packet_count": 0,
                    "icon": get_os_icon(os_guess)
                }
            else:
                st.session_state.os_detections[src_ip]["last_seen"] = datetime.now()
                st.session_state.os_detections[src_ip]["packet_count"] += 1

            # Hping3 flood detection - SYN flood pattern
            if pkt[TCP].flags == "S" or str(pkt[TCP].flags) == "S":
                st.session_state.conn_tracker[pkt[IP].src] += 1

                # If this IP is suspected of hping3 flood
                if st.session_state.conn_tracker[pkt[IP].src] > 50:
                    # Auto-block if threshold exceeded
                    if pkt[IP].src not in st.session_state.blocked_ips:
                        block_action = create_block_action(
                            pkt[IP].src,
                            "SYN Flood / hping3 Attack",
                            f"Blocked after {st.session_state.conn_tracker[pkt[IP].src]} SYN packets",
                            "AUTO"
                        )
                        st.session_state.active_blocks.append(block_action)
                        st.session_state.blocked_ips.add(pkt[IP].src)

                    alert = create_alert(pkt[IP].src, pkt[IP].dst, "T1499",
                                         "Endpoint DoS",
                                         f"hping3-style SYN flood detected: {st.session_state.conn_tracker[pkt[IP].src]} SYN packets",
                                         15, "Impact")

            # Port scan detection
            key = pkt[IP].src
            st.session_state.port_scan_tracker[key].add(pkt[TCP].dport)
            if len(st.session_state.port_scan_tracker[key]) > 20:
                alert = create_alert(pkt[IP].src, pkt[IP].dst, "T1046",
                                     "Network Service Scanning",
                                     f"Port scan detected: {len(st.session_state.port_scan_tracker[key])} ports probed",
                                     10, "Discovery")

            # Suspicious port
            if pkt[TCP].dport in SUSPICIOUS_PORTS:
                name, tactic, level = SUSPICIOUS_PORTS[pkt[TCP].dport]
                if level >= 7:
                    alert = create_alert(pkt[IP].src, pkt[IP].dst, "T1071",
                                         tactic,
                                         f"Suspicious connection to {name} (port {pkt[TCP].dport})",
                                         level, tactic)

        elif UDP in pkt:
            packet_info["proto"] = "UDP"
            packet_info["sport"] = pkt[UDP].sport
            packet_info["dport"] = pkt[UDP].dport

            # UDP flood detection (hping3 --udp --flood)
            st.session_state.conn_tracker[f"udp_{pkt[IP].src}"] = \
                st.session_state.conn_tracker.get(f"udp_{pkt[IP].src}", 0) + 1

            if st.session_state.conn_tracker.get(f"udp_{pkt[IP].src}", 0) > 100:
                if pkt[IP].src not in st.session_state.blocked_ips:
                    block_action = create_block_action(
                        pkt[IP].src,
                        "UDP Flood / hping3 --udp Attack",
                        f"Blocked after UDP flood detection",
                        "AUTO"
                    )
                    st.session_state.active_blocks.append(block_action)
                    st.session_state.blocked_ips.add(pkt[IP].src)
                alert = create_alert(pkt[IP].src, pkt[IP].dst, "T1499",
                                     "UDP Flood",
                                     f"hping3-style UDP flood detected",
                                     12, "Impact")

            if DNS in pkt and pkt.haslayer(DNS):
                try:
                    if pkt[DNS].qd:
                        qname = pkt[DNS].qd.qname.decode(errors='ignore')
                        if len(qname) > 50:
                            alert = create_alert(pkt[IP].src, pkt[IP].dst, "T1071",
                                                 "DNS Tunneling",
                                                 f"Suspiciously long DNS query: {qname[:60]}",
                                                 9, "Command and Control")
                except:
                    pass

        elif ICMP in pkt:
            packet_info["proto"] = "ICMP"

            # ICMP flood detection (hping3 --icmp --flood)
            st.session_state.conn_tracker[f"icmp_{pkt[IP].src}"] = \
                st.session_state.conn_tracker.get(f"icmp_{pkt[IP].src}", 0) + 1

            if st.session_state.conn_tracker.get(f"icmp_{pkt[IP].src}", 0) > 50:
                if pkt[IP].src not in st.session_state.blocked_ips:
                    block_action = create_block_action(
                        pkt[IP].src,
                        "ICMP Flood / hping3 --icmp Attack",
                        f"Blocked after ICMP flood detection",
                        "AUTO"
                    )
                    st.session_state.active_blocks.append(block_action)
                    st.session_state.blocked_ips.add(pkt[IP].src)
                alert = create_alert(pkt[IP].src, pkt[IP].dst, "T1499",
                                     "ICMP Flood",
                                     f"hping3-style ICMP flood detected",
                                     12, "Impact")

    elif ARP in pkt:
        packet_info["proto"] = "ARP"
        packet_info["src"] = pkt[ARP].psrc
        packet_info["dst"] = pkt[ARP].pdst

    return packet_info, alert


def create_alert(src, dst, tech_id, technique, description, level, tactic):
    return {
        "timestamp": datetime.now(),
        "src": src,
        "dst": dst,
        "technique_id": tech_id,
        "technique": technique,
        "description": description,
        "level": level,
        "tactic": tactic,
        "rule_id": np.random.randint(100000, 999999),
        "agent": socket.gethostname()
    }


def create_block_action(src_ip, reason, details, block_type="MANUAL"):
    return {
        "timestamp": datetime.now(),
        "src_ip": src_ip,
        "reason": reason,
        "details": details,
        "block_type": block_type,
        "status": "ACTIVE",
        "rule_id": np.random.randint(100000, 999999),
        "expires": (datetime.now() + timedelta(hours=1)).strftime("%H:%M:%S")
    }


# ---------------- CAPTURE THREAD ----------------
def packet_callback(pkt, pkt_queue, alert_queue):
    try:
        info, alert = analyze_packet(pkt)
        pkt_queue.put(info)
        if alert:
            alert_queue.put(alert)
    except Exception as e:
        pass


def start_capture(interface, pkt_queue, alert_queue, stop_event):
    try:
        sniff(iface=interface if interface != "Any" else None,
              prn=lambda p: packet_callback(p, pkt_queue, alert_queue),
              stop_filter=lambda x: stop_event.is_set(),
              store=False)
    except Exception as e:
        print(f"Capture error: {e}")


# ---------------- SIMULATED DATA GENERATION ----------------
def generate_simulated_data():
    """Generate realistic simulated network data for demo purposes"""

    # Simulated IPs with OS types
    endpoints = [
        {"ip": "192.168.1.10", "os": "Windows (Modern)", "hostname": "WORKSTATION-01"},
        {"ip": "192.168.1.11", "os": "Linux/Unix", "hostname": "WEBSERVER-01"},
        {"ip": "192.168.1.12", "os": "macOS/iOS", "hostname": "MAC-DEV-01"},
        {"ip": "192.168.1.20", "os": "Windows", "hostname": "DC-SERVER"},
        {"ip": "192.168.1.30", "os": "Linux/Unix", "hostname": "FILESERVER"},
        {"ip": "10.0.0.5", "os": "Cisco/Network Device", "hostname": "CORE-SWITCH"},
        {"ip": "172.16.0.100", "os": "Unknown", "hostname": "UNKNOWN-HOST"},
    ]

    # Attacker IPs (hping3 sources)
    attackers = [
        "203.0.113.45",
        "198.51.100.22",
        "203.0.113.99",
    ]

    protocols = ["TCP", "UDP", "ICMP", "ARP", "DNS"]

    # Generate packets
    packets_to_add = []
    alerts_to_add = []

    num_packets = random.randint(5, 20)

    for _ in range(num_packets):
        src_endpoint = random.choice(
            endpoints + [{"ip": random.choice(attackers), "os": "Linux/Unix", "hostname": "ATTACKER"}])
        dst_endpoint = random.choice(endpoints)
        proto = random.choice(protocols)

        # Update OS detections
        if src_endpoint["ip"] not in st.session_state.os_detections:
            st.session_state.os_detections[src_endpoint["ip"]] = {
                "os": src_endpoint.get("os", "Unknown"),
                "ttl": 64 if "Linux" in src_endpoint.get("os", "") else 128,
                "window_size": 65535 if "Windows" in src_endpoint.get("os", "") else 5840,
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "packet_count": 0,
                "hostname": src_endpoint.get("hostname", "Unknown"),
                "icon": get_os_icon(src_endpoint.get("os", "Unknown"))
            }
        else:
            st.session_state.os_detections[src_endpoint["ip"]]["last_seen"] = datetime.now()
            st.session_state.os_detections[src_endpoint["ip"]]["packet_count"] += 1

        pkt = {
            "timestamp": datetime.now(),
            "src": src_endpoint["ip"],
            "dst": dst_endpoint["ip"],
            "sport": random.randint(1024, 65535),
            "dport": random.choice([80, 443, 22, 3389, 445, 8080, 3306, 4444, 6667, 31337]),
            "proto": proto,
            "length": random.randint(40, 1500),
            "flags": random.choice(["S", "SA", "A", "F", "R", "PA"]),
            "ttl": 64 if "Linux" in src_endpoint.get("os", "") else 128,
            "os_guess": src_endpoint.get("os", "Unknown"),
            "window_size": random.choice([8192, 65535, 5840, 29200])
        }
        packets_to_add.append(pkt)

        # Check if this is a hping3 attack simulation
        if st.session_state.hping3_attack and src_endpoint["ip"] in attackers:
            # Generate flood packets
            flood_packets = []
            for i in range(random.randint(10, 30)):
                flood_pkt = pkt.copy()
                flood_pkt["timestamp"] = datetime.now()
                flood_pkt["src"] = st.session_state.hping3_target if st.session_state.hping3_target else random.choice(
                    attackers)
                flood_pkt["flags"] = "S"  # SYN flood
                flood_pkt["proto"] = "TCP"
                flood_packets.append(flood_pkt)

                # Update SYN counter
                attacker_ip = flood_pkt["src"]
                st.session_state.conn_tracker[attacker_ip] = \
                    st.session_state.conn_tracker.get(attacker_ip, 0) + 1

                if st.session_state.conn_tracker.get(attacker_ip, 0) > 50:
                    if attacker_ip not in st.session_state.blocked_ips:
                        block = create_block_action(
                            attacker_ip,
                            "SYN Flood / hping3 --flood Detected",
                            f"Automated block: {st.session_state.conn_tracker[attacker_ip]} SYN packets/sec",
                            "AUTO-IPS"
                        )
                        st.session_state.active_blocks.append(block)
                        st.session_state.blocked_ips.add(attacker_ip)

                        alert = create_alert(
                            attacker_ip,
                            dst_endpoint["ip"],
                            "T1499",
                            "Endpoint DoS",
                            f"🚨 hping3 --flood DETECTED! {st.session_state.conn_tracker[attacker_ip]} packets/sec from {attacker_ip}",
                            15,
                            "Impact"
                        )
                        alerts_to_add.append(alert)

            packets_to_add.extend(flood_packets)
            st.session_state.hping3_stats["packets_sent"] += len(flood_packets)

    # Random alerts
    if random.random() < 0.3:
        alert_types = [
            ("T1046", "Network Service Scanning", "Port scan detected from external IP", 10, "Discovery",
             random.choice(attackers)),
            ("T1110", "Brute Force", "SSH brute force attempt detected", 8, "Credential Access",
             random.choice(attackers)),
            ("T1071", "C2 Communication", "Suspicious beacon traffic to C2 server", 12, "Command and Control",
             random.choice(attackers)),
            ("T1595", "Active Scanning", "Active reconnaissance scan detected", 9, "Reconnaissance",
             random.choice(attackers)),
        ]
        a_type = random.choice(alert_types)
        dst = random.choice(endpoints)
        alert = create_alert(a_type[5], dst["ip"], a_type[0], a_type[1], a_type[2], a_type[3], a_type[4])
        alerts_to_add.append(alert)

    return packets_to_add, alerts_to_add


# ---------------- UI HELPERS ----------------
def load_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    * { font-family: 'Inter', sans-serif; }

    .metric-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
        padding: 20px;
        border-radius: 16px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.06);
        text-align: center;
        border: 1px solid #e2e8f0;
        transition: transform 0.2s;
    }
    .metric-card:hover { transform: translateY(-2px); }
    .metric-title { color: #64748b; font-size: 13px; font-weight: 500; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
    .metric-value-blue { color: #2563eb; font-size: 38px; font-weight: 700; }
    .metric-value-red  { color: #dc2626; font-size: 38px; font-weight: 700; }
    .metric-value-green { color: #16a34a; font-size: 38px; font-weight: 700; }
    .metric-value-orange { color: #ea580c; font-size: 38px; font-weight: 700; }

    .os-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        padding: 16px;
        border-radius: 12px;
        margin: 8px 0;
        border-left: 4px solid #3b82f6;
        color: white;
    }
    .os-card-ip { font-size: 15px; font-weight: 600; color: #60a5fa; }
    .os-card-os { font-size: 13px; color: #94a3b8; margin-top: 4px; }
    .os-card-stats { font-size: 12px; color: #64748b; margin-top: 6px; }

    .block-card {
        background: linear-gradient(135deg, #fef2f2 0%, #fff1f1 100%);
        padding: 14px;
        border-radius: 10px;
        margin: 6px 0;
        border-left: 4px solid #ef4444;
    }
    .block-ip { font-size: 14px; font-weight: 700; color: #dc2626; }
    .block-reason { font-size: 12px; color: #64748b; margin-top: 4px; }
    .block-time { font-size: 11px; color: #9ca3af; margin-top: 4px; }

    .hping3-card {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        padding: 20px;
        border-radius: 16px;
        border: 1px solid #f87171;
        box-shadow: 0 0 20px rgba(248, 113, 113, 0.2);
    }
    .hping3-title { color: #f87171; font-size: 18px; font-weight: 700; }
    .hping3-stats { color: #94a3b8; font-size: 13px; margin-top: 8px; }
    .hping3-value { color: #fbbf24; font-size: 28px; font-weight: 700; }

    .alert-critical {
        background: linear-gradient(135deg, #450a0a 0%, #7f1d1d 100%);
        padding: 12px 16px;
        border-radius: 8px;
        border-left: 4px solid #ef4444;
        color: white;
        margin: 6px 0;
        animation: pulse 2s infinite;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.85; }
    }

    .section-header {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        color: white;
        padding: 10px 16px;
        border-radius: 10px;
        font-size: 14px;
        font-weight: 600;
        margin-bottom: 12px;
        border-left: 4px solid #3b82f6;
    }

    .stApp { background: #0f172a; }

    div[data-testid="stVerticalBlock"] > div:has(div.stTabs) {
        background: transparent;
    }

    .status-badge-running {
        background: #166534;
        color: #4ade80;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    .status-badge-stopped {
        background: #7f1d1d;
        color: #fca5a5;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }

    .timeline-item {
        border-left: 2px solid #3b82f6;
        padding-left: 16px;
        margin: 8px 0;
        position: relative;
    }
    .timeline-item::before {
        content: '';
        width: 10px;
        height: 10px;
        background: #3b82f6;
        border-radius: 50%;
        position: absolute;
        left: -6px;
        top: 4px;
    }

    /* Dark theme overrides */
    .stTabs [data-baseweb="tab-list"] {
        background: #1e293b;
        border-radius: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        color: #94a3b8;
    }
    .stTabs [aria-selected="true"] {
        color: #3b82f6;
    }
    </style>
    """, unsafe_allow_html=True)


def metric_card(title, value, color="blue", subtitle=""):
    color_class = f"metric-value-{color}"
    sub_html = f'<div style="font-size:11px;color:#94a3b8;margin-top:4px">{subtitle}</div>' if subtitle else ""
    return f"""
    <div class="metric-card">
        <div class="metric-title">{title}</div>
        <div class="{color_class}">{value}</div>
        {sub_html}
    </div>
    """


# ---------------- DRAIN QUEUES ----------------
def drain_queues():
    q = st.session_state.packet_queue
    aq = st.session_state.alert_queue
    drained = 0
    while not q.empty() and drained < 500:
        try:
            pkt = q.get_nowait()
            st.session_state.packets.append(pkt)
            st.session_state.stats["total"] += 1
            proto = pkt["proto"].lower()
            if proto in st.session_state.stats:
                st.session_state.stats[proto] += 1
            st.session_state.agent_counts[socket.gethostname()] += 1
            drained += 1
        except queue.Empty:
            break

    while not aq.empty():
        try:
            a = aq.get_nowait()
            st.session_state.alerts.append(a)
            if a["level"] >= 12:
                st.session_state.stats["high_alerts"] += 1
            if "Brute" in a["technique"] or "Password" in a["technique"]:
                st.session_state.stats["auth_failure"] += 1
            st.session_state.mitre_counts[a["technique"]] += 1
        except queue.Empty:
            break

    # If capture running and using simulation
    if st.session_state.capture_running and not SCAPY_AVAILABLE:
        packets_sim, alerts_sim = generate_simulated_data()
        for pkt in packets_sim:
            st.session_state.packets.append(pkt)
            st.session_state.stats["total"] += 1
            proto = pkt["proto"].lower()
            if proto in st.session_state.stats:
                st.session_state.stats[proto] += 1

        for alert in alerts_sim:
            st.session_state.alerts.append(alert)
            if alert["level"] >= 12:
                st.session_state.stats["high_alerts"] += 1
            if "Brute" in alert["technique"] or "Password" in alert["technique"]:
                st.session_state.stats["auth_failure"] += 1
            if "auth" in alert["technique"].lower() or "login" in alert["description"].lower():
                st.session_state.stats["auth_success"] += random.randint(0, 2)
            st.session_state.mitre_counts[alert["technique"]] += 1


# ================ MAIN APP ================
load_css()

# ---- Header ----
header_col1, header_col2, header_col3, header_col4 = st.columns([1, 3, 2, 1])
with header_col1:
    st.markdown("### 🛡️ **SOC Platform**")
with header_col2:
    st.markdown("## 🔍 Threat Hunting Dashboard")
with header_col3:
    status_text = "🟢 CAPTURING" if st.session_state.capture_running else "🔴 IDLE"
    st.markdown(f"**Status:** {status_text} | **{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}**")
with header_col4:
    total_blocks = len(st.session_state.active_blocks)
    if total_blocks > 0:
        st.markdown(f"🚫 **{total_blocks} BLOCKED**")

# ---- Sidebar ----
with st.sidebar:
    st.markdown("### ⚙️ Capture Controls")

    if not SCAPY_AVAILABLE:
        st.warning("⚠️ Scapy not installed - Running in **Simulation Mode**")
        st.info("Install: `pip install scapy`")
    else:
        try:
            interfaces = ["Any"] + get_if_list()
        except:
            interfaces = ["Any"]
        selected_iface = st.selectbox("Network Interface", interfaces)

    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("▶️ Start", use_container_width=True, type="primary"):
            if not st.session_state.capture_running:
                st.session_state.capture_running = True
                if SCAPY_AVAILABLE:
                    st.session_state.stop_event = threading.Event()
                    t = threading.Thread(
                        target=start_capture,
                        args=(selected_iface, st.session_state.packet_queue,
                              st.session_state.alert_queue, st.session_state.stop_event),
                        daemon=True
                    )
                    t.start()
                    st.session_state.capture_thread = t
                st.success("✅ Started!")
    with col_b:
        if st.button("⏹️ Stop", use_container_width=True):
            if st.session_state.capture_running:
                st.session_state.capture_running = False
                if SCAPY_AVAILABLE and hasattr(st.session_state, "stop_event"):
                    st.session_state.stop_event.set()
                st.session_state.hping3_attack = False
                st.warning("⏹️ Stopped")

    st.divider()

    # ---- hping3 Attack Simulation ----
    st.markdown("### 🔥 hping3 Attack Simulator")

    attack_type = st.selectbox("Attack Type", [
        "SYN Flood (--flood --syn)",
        "UDP Flood (--flood --udp)",
        "ICMP Flood (--flood --icmp)",
        "XMAS Scan (--xmas)",
        "FIN Scan (--fin)",
        "Land Attack (--land)"
    ])

    target_ip = st.text_input("Target IP", value="192.168.1.1", placeholder="Enter target IP")

    col_c, col_d = st.columns(2)
    with col_c:
        if st.button("💥 Launch", use_container_width=True, type="primary"):
            if not st.session_state.capture_running:
                st.error("Start capture first!")
            else:
                st.session_state.hping3_attack = True
                st.session_state.hping3_target = target_ip
                st.session_state.hping3_stats = {
                    "packets_sent": 0,
                    "start_time": datetime.now(),
                    "attack_type": attack_type,
                    "target": target_ip
                }
                st.success(f"🚨 Attack launched on {target_ip}!")
    with col_d:
        if st.button("🛑 Stop Atk", use_container_width=True):
            st.session_state.hping3_attack = False
            st.session_state.hping3_target = ""
            st.success("Attack stopped")

    if st.session_state.hping3_attack:
        elapsed = ""
        if st.session_state.hping3_stats["start_time"]:
            delta = datetime.now() - st.session_state.hping3_stats["start_time"]
            elapsed = f"{int(delta.total_seconds())}s"

        st.markdown(f"""
        <div class="hping3-card">
            <div class="hping3-title">🚨 ATTACK ACTIVE</div>
            <div class="hping3-stats">Type: {st.session_state.hping3_stats['attack_type']}</div>
            <div class="hping3-stats">Target: {st.session_state.hping3_stats['target']}</div>
            <div class="hping3-value">{st.session_state.hping3_stats['packets_sent']:,}</div>
            <div class="hping3-stats">Packets sent | Duration: {elapsed}</div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    st.markdown("### 🔄 Refresh")
    auto_refresh = st.checkbox("Auto Refresh", value=True)
    refresh_rate = st.slider("Rate (sec)", 1, 10, 2)

    st.divider()

    # Manual IP block
    st.markdown("### 🚫 Manual Block IP")
    block_ip_input = st.text_input("IP to Block", placeholder="Enter IP address")
    block_reason = st.text_input("Reason", placeholder="Why blocking?")
    if st.button("🚫 Block IP", use_container_width=True):
        if block_ip_input:
            block = create_block_action(block_ip_input, block_reason or "Manual block", "Manually blocked by analyst",
                                        "MANUAL")
            st.session_state.active_blocks.append(block)
            st.session_state.blocked_ips.add(block_ip_input)
            st.success(f"Blocked {block_ip_input}")

    st.divider()

    if st.button("🧹 Clear All Data", use_container_width=True):
        st.session_state.packets.clear()
        st.session_state.alerts.clear()
        st.session_state.active_blocks.clear()
        st.session_state.os_detections.clear()
        st.session_state.blocked_ips.clear()
        st.session_state.stats = {k: 0 for k in st.session_state.stats}
        st.session_state.port_scan_tracker.clear()
        st.session_state.conn_tracker.clear()
        st.session_state.mitre_counts.clear()
        st.session_state.agent_counts.clear()
        st.session_state.hping3_attack = False
        st.session_state.hping3_stats = {"packets_sent": 0, "start_time": None, "attack_type": "", "target": ""}
        st.success("✅ All data cleared")

# ---- Drain queues ----
drain_queues()

# ---- Tabs ----
tab_dash, tab_os, tab_hping3, tab_blocks, tab_events, tab_alerts, tab_packets = st.tabs([
    "📊 Dashboard",
    "💻 Endpoint OS",
    "🔥 hping3 Monitor",
    "🚫 Active Blocks",
    "📋 Events",
    "🚨 Security Alerts",
    "📦 Live Packets"
])

# ================== DASHBOARD TAB ==================
with tab_dash:
    # Search
    c1, c2, c3 = st.columns([4, 1, 1])
    with c1:
        search_q = st.text_input("🔍", label_visibility="collapsed",
                                 placeholder="Search IP / port / technique / OS...")
    with c2:
        st.button("📡 Agent Explorer", use_container_width=True)
    with c3:
        st.button("📄 Export Report", use_container_width=True)

    # KPI Row 1
    stats = st.session_state.stats
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    with m1:
        st.markdown(metric_card("📦 Total Packets", f"{stats['total']:,}", "blue",
                                f"TCP:{stats['tcp']} UDP:{stats['udp']}"), unsafe_allow_html=True)
    with m2:
        st.markdown(metric_card("🚨 Critical Alerts", stats["high_alerts"], "red",
                                "Level 12+"), unsafe_allow_html=True)
    with m3:
        st.markdown(metric_card("❌ Auth Failures", stats["auth_failure"], "red",
                                "Brute Force"), unsafe_allow_html=True)
    with m4:
        st.markdown(metric_card("✅ Auth Success", stats["auth_success"], "green",
                                "Legitimate"), unsafe_allow_html=True)
    with m5:
        st.markdown(metric_card("🚫 Blocked IPs", len(st.session_state.blocked_ips), "orange",
                                "Active Blocks"), unsafe_allow_html=True)
    with m6:
        os_count = len(st.session_state.os_detections)
        st.markdown(metric_card("💻 Endpoints", os_count, "blue",
                                "Detected"), unsafe_allow_html=True)

    st.markdown("---")

    # hping3 attack banner
    if st.session_state.hping3_attack:
        elapsed_s = ""
        if st.session_state.hping3_stats["start_time"]:
            delta = datetime.now() - st.session_state.hping3_stats["start_time"]
            elapsed_s = f"{int(delta.total_seconds())}s"

        st.markdown(f"""
        <div class="alert-critical">
            🚨 <strong>ACTIVE ATTACK:</strong> hping3 {st.session_state.hping3_stats['attack_type']} 
            → Target: <strong>{st.session_state.hping3_stats['target']}</strong> | 
            Packets: <strong>{st.session_state.hping3_stats['packets_sent']:,}</strong> | 
            Duration: <strong>{elapsed_s}</strong> |
            IPS Status: <strong>{'🛡️ BLOCKING' if st.session_state.blocked_ips else '⚠️ DETECTING'}</strong>
        </div>
        """, unsafe_allow_html=True)

    # Charts Row 1
    c1, c2, c3 = st.columns([2, 2, 1])

    with c1:
        st.markdown('<div class="section-header">📈 Alert Level Timeline</div>', unsafe_allow_html=True)
        if len(st.session_state.alerts) > 0:
            df_a = pd.DataFrame(list(st.session_state.alerts))
            df_a["minute"] = df_a["timestamp"].dt.floor("min")
            agg = df_a.groupby(["minute", "level"]).size().reset_index(name="count")
            fig = px.area(agg, x="minute", y="count", color="level",
                          color_discrete_sequence=["#ef4444", "#f97316", "#eab308", "#3b82f6"])
            fig.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0),
                              plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
                              font=dict(color="white"),
                              legend=dict(orientation="h", y=-0.2))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Start capture to see timeline data")

    with c2:
        st.markdown('<div class="section-header">🗺️ MITRE ATT&CK Heatmap</div>', unsafe_allow_html=True)
        if st.session_state.mitre_counts:
            df_m = pd.DataFrame(list(st.session_state.mitre_counts.items()),
                                columns=["Technique", "Count"])
            df_m = df_m.sort_values("Count", ascending=True)
            fig = go.Figure(go.Bar(
                x=df_m["Count"], y=df_m["Technique"],
                orientation='h',
                marker=dict(
                    color=df_m["Count"],
                    colorscale="Reds",
                    showscale=True
                )
            ))
            fig.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0),
                              plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
                              font=dict(color="white"))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No MITRE techniques detected")

    with c3:
        st.markdown('<div class="section-header">🔌 Protocols</div>', unsafe_allow_html=True)
        proto_data = {k: v for k, v in stats.items()
                      if k in ["tcp", "udp", "icmp", "arp", "dns"] and v > 0}
        if proto_data:
            fig = go.Figure(go.Pie(
                values=list(proto_data.values()),
                labels=[k.upper() for k in proto_data.keys()],
                hole=0.65,
                marker=dict(colors=["#3b82f6", "#8b5cf6", "#06b6d4", "#10b981", "#f59e0b"])
            ))
            fig.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0),
                              paper_bgcolor="#1e293b", font=dict(color="white"),
                              showlegend=True, legend=dict(orientation="v", x=0.8))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No protocol data")

    # Charts Row 2
    c4, c5 = st.columns([1, 2])

    with c4:
        st.markdown('<div class="section-header">💻 OS Distribution</div>', unsafe_allow_html=True)
        if st.session_state.os_detections:
            os_counts = defaultdict(int)
            for ip, data in st.session_state.os_detections.items():
                os_counts[data["os"]] += 1

            df_os = pd.DataFrame(list(os_counts.items()), columns=["OS", "Count"])
            fig = px.pie(df_os, values="Count", names="OS", hole=0.6,
                         color_discrete_sequence=["#3b82f6", "#8b5cf6", "#f59e0b", "#10b981", "#ef4444"])
            fig.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0),
                              paper_bgcolor="#1e293b", font=dict(color="white"))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No endpoint data")

    with c5:
        st.markdown('<div class="section-header">📊 Traffic Evolution - Top Sources</div>', unsafe_allow_html=True)
        if len(st.session_state.packets) > 0:
            df_p = pd.DataFrame(list(st.session_state.packets))
            df_p["minute"] = df_p["timestamp"].dt.floor("min")
            top_src = df_p["src"].value_counts().head(5).index.tolist()
            df_top = df_p[df_p["src"].isin(top_src)]
            agg = df_top.groupby(["minute", "src"]).size().reset_index(name="count")
            fig = px.bar(agg, x="minute", y="count", color="src", barmode="stack",
                         color_discrete_sequence=["#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6"])
            fig.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0),
                              plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
                              font=dict(color="white"),
                              legend=dict(orientation="h", y=-0.3))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No traffic data yet")

    # Alert Table
    st.markdown('<div class="section-header">🚨 Latest Security Alerts</div>', unsafe_allow_html=True)
    if len(st.session_state.alerts) > 0:
        df_alerts = pd.DataFrame(list(st.session_state.alerts)[-15:][::-1])
        cols_to_show = [c for c in ["timestamp", "agent", "src", "dst", "technique_id",
                                    "tactic", "description", "level", "rule_id"] if c in df_alerts.columns]
        df_alerts = df_alerts[cols_to_show]
        df_alerts.columns = ["Time", "Agent", "Source", "Destination", "Technique",
                             "Tactic", "Description", "Level", "Rule ID"][:len(cols_to_show)]
        if search_q:
            mask = df_alerts.astype(str).apply(lambda x: x.str.contains(search_q, case=False)).any(axis=1)
            df_alerts = df_alerts[mask]

        st.dataframe(
            df_alerts.style.apply(
                lambda x: ['background-color: #450a0a; color: white' if i == 'Level' and v >= 12
                           else '' for i, v in zip(x.index, x)],
                axis=1
            ),
            use_container_width=True, hide_index=True
        )
    else:
        st.info("No security alerts - start capture to detect threats")

# ================== OS DETECTION TAB ==================
with tab_os:
    st.markdown("## 💻 Endpoint OS Detection")
    st.markdown("*Real-time OS fingerprinting based on TTL, TCP window size, and packet characteristics*")

    if not st.session_state.os_detections:
        st.info("🔍 No endpoints detected yet. Start capture to begin OS fingerprinting.")

        # Show example
        st.markdown("### 📖 OS Detection Methodology")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("""
            **🐧 Linux/Unix Detection**
            - TTL: 64
            - TCP Window: 5840-29200
            - Stack: IPID sequential
            """)
        with col2:
            st.markdown("""
            **🪟 Windows Detection**  
            - TTL: 128
            - TCP Window: 8192-65535
            - Stack: IPID random
            """)
        with col3:
            st.markdown("""
            **🍎 macOS Detection**
            - TTL: 64
            - TCP Window: 65535
            - Stack: BSD-derived
            """)
    else:
        # OS Summary metrics
        os_summary = defaultdict(int)
        for ip, data in st.session_state.os_detections.items():
            os_summary[data["os"]] += 1

        # Display OS counts
        os_cols = st.columns(min(len(os_summary), 5))
        for i, (os_name, count) in enumerate(os_summary.items()):
            if i < len(os_cols):
                icon = get_os_icon(os_name)
                with os_cols[i]:
                    st.markdown(metric_card(f"{icon} {os_name}", count, "blue"), unsafe_allow_html=True)

        st.markdown("---")

        # Search and filter
        col_f1, col_f2 = st.columns([3, 1])
        with col_f1:
            os_search = st.text_input("🔍 Search endpoint", placeholder="Search by IP, OS, hostname...")
        with col_f2:
            os_filter = st.selectbox("Filter by OS", ["All"] + list(os_summary.keys()))

        # Endpoint cards
        st.markdown("### 🖥️ Detected Endpoints")

        # Create grid
        endpoints_list = list(st.session_state.os_detections.items())
        if os_filter != "All":
            endpoints_list = [(ip, d) for ip, d in endpoints_list if d["os"] == os_filter]
        if os_search:
            endpoints_list = [(ip, d) for ip, d in endpoints_list
                              if os_search.lower() in ip.lower() or
                              os_search.lower() in d.get("os", "").lower() or
                              os_search.lower() in d.get("hostname", "").lower()]

        # Display in 3-column grid
        cols_per_row = 3
        for i in range(0, len(endpoints_list), cols_per_row):
            cols = st.columns(cols_per_row)
            for j, (ip, data) in enumerate(endpoints_list[i:i + cols_per_row]):
                with cols[j]:
                    is_blocked = ip in st.session_state.blocked_ips
                    block_badge = "🚫 BLOCKED" if is_blocked else "✅ ACTIVE"
                    block_color = "#ef4444" if is_blocked else "#10b981"

                    threat_level = "⚠️ HIGH" if is_blocked else "✅ LOW"

                    last_seen = data.get("last_seen", datetime.now())
                    if isinstance(last_seen, datetime):
                        last_seen_str = last_seen.strftime("%H:%M:%S")
                    else:
                        last_seen_str = "N/A"

                    first_seen = data.get("first_seen", datetime.now())
                    if isinstance(first_seen, datetime):
                        first_seen_str = first_seen.strftime("%H:%M:%S")
                    else:
                        first_seen_str = "N/A"

                    st.markdown(f"""
                    <div class="os-card" style="border-left-color: {block_color};">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div class="os-card-ip">{data.get('icon', '❓')} {ip}</div>
                            <span style="background:{block_color}20; color:{block_color}; 
                                         padding:2px 8px; border-radius:10px; font-size:11px;">
                                {block_badge}
                            </span>
                        </div>
                        <div class="os-card-os">{data.get('os', 'Unknown')}</div>
                        <div class="os-card-stats">
                            🏠 {data.get('hostname', 'Unknown hostname')}<br>
                            📊 TTL: {data.get('ttl', 'N/A')} | Window: {data.get('window_size', 'N/A')}<br>
                            📦 Packets: {data.get('packet_count', 0):,}<br>
                            🕐 First: {first_seen_str} | Last: {last_seen_str}<br>
                            ⚠️ Threat Level: {threat_level}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    if not is_blocked:
                        if st.button(f"🚫 Block {ip}", key=f"block_{ip}", use_container_width=True):
                            block = create_block_action(ip, "Manual block from OS tab", "Blocked by analyst", "MANUAL")
                            st.session_state.active_blocks.append(block)
                            st.session_state.blocked_ips.add(ip)
                            st.rerun()
                    else:
                        if st.button(f"✅ Unblock {ip}", key=f"unblock_{ip}", use_container_width=True):
                            st.session_state.blocked_ips.discard(ip)
                            # Remove from active blocks
                            st.session_state.active_blocks = deque(
                                [b for b in st.session_state.active_blocks if b["src_ip"] != ip],
                                maxlen=500
                            )
                            st.rerun()

        st.markdown("---")

        # OS Detection table
        st.markdown("### 📋 OS Fingerprint Table")
        if st.session_state.os_detections:
            os_df_data = []
            for ip, data in st.session_state.os_detections.items():
                os_df_data.append({
                    "IP Address": ip,
                    "Hostname": data.get("hostname", "Unknown"),
                    "OS": f"{data.get('icon', '')} {data.get('os', 'Unknown')}",
                    "TTL": data.get("ttl", "N/A"),
                    "Window Size": data.get("window_size", "N/A"),
                    "Packets": data.get("packet_count", 0),
                    "Status": "🚫 BLOCKED" if ip in st.session_state.blocked_ips else "✅ ACTIVE",
                    "First Seen": data.get("first_seen", datetime.now()).strftime("%H:%M:%S") if isinstance(
                        data.get("first_seen"), datetime) else "N/A",
                    "Last Seen": data.get("last_seen", datetime.now()).strftime("%H:%M:%S") if isinstance(
                        data.get("last_seen"), datetime) else "N/A"
                })

            df_os_table = pd.DataFrame(os_df_data)
            st.dataframe(df_os_table, use_container_width=True, hide_index=True, height=400)

            csv = df_os_table.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download OS Report", csv, "os_detections.csv", "text/csv")

# ================== HPING3 MONITOR TAB ==================
with tab_hping3:
    st.markdown("## 🔥 hping3 Attack Monitor & IPS Response")

    # Attack status
    if st.session_state.hping3_attack:
        elapsed_time = ""
        pps = 0
        if st.session_state.hping3_stats["start_time"]:
            delta = datetime.now() - st.session_state.hping3_stats["start_time"]
            elapsed_secs = int(delta.total_seconds())
            elapsed_time = f"{elapsed_secs}s"
            pps = st.session_state.hping3_stats["packets_sent"] // max(elapsed_secs, 1)

        # Big attack status
        st.markdown(f"""
        <div class="hping3-card" style="margin-bottom: 20px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <div class="hping3-title">🚨 ACTIVE FLOOD ATTACK DETECTED</div>
                    <div class="hping3-stats" style="margin-top:8px;">
                        Attack: <strong style="color:#fbbf24">{st.session_state.hping3_stats['attack_type']}</strong>
                    </div>
                    <div class="hping3-stats">Target: <strong style="color:#f87171">{st.session_state.hping3_stats['target']}</strong></div>
                </div>
                <div style="text-align:right;">
                    <div class="hping3-value">{st.session_state.hping3_stats['packets_sent']:,}</div>
                    <div class="hping3-stats">Total Packets</div>
                    <div style="color:#4ade80; font-size:18px; font-weight:600; margin-top:4px;">{pps:,} pps</div>
                    <div class="hping3-stats">Packets/Second | Duration: {elapsed_time}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("💤 No active hping3 attack. Use the sidebar to simulate an attack.")

    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        attack_packets = st.session_state.hping3_stats.get("packets_sent", 0)
        st.markdown(metric_card("💥 Attack Packets", f"{attack_packets:,}", "red", "hping3 Sent"),
                    unsafe_allow_html=True)
    with col2:
        blocked = len(st.session_state.blocked_ips)
        st.markdown(metric_card("🛡️ IPS Blocks", blocked, "green", "Auto-blocked"), unsafe_allow_html=True)
    with col3:
        syn_attacks = sum(1 for a in st.session_state.alerts if
                          "SYN" in a.get("description", "") or "flood" in a.get("description", "").lower())
        st.markdown(metric_card("🚨 Flood Alerts", syn_attacks, "red", "Triggered"), unsafe_allow_html=True)
    with col4:
        icmp_count = stats.get("icmp", 0)
        st.markdown(metric_card("🏓 ICMP Packets", icmp_count, "orange", "Echo/Flood"), unsafe_allow_html=True)

    st.markdown("---")

    # Attack simulation info
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("### 🔧 hping3 Command Reference")

        commands = {
            "SYN Flood": "hping3 --flood --syn -p 80 {target}",
            "UDP Flood": "hping3 --flood --udp -p 80 {target}",
            "ICMP Flood": "hping3 --flood --icmp {target}",
            "XMAS Scan": "hping3 --xmas -p 80 {target}",
            "FIN Scan": "hping3 --fin -p 80 {target}",
            "Land Attack": "hping3 --land -S -p 80 {target}",
            "Ping of Death": "hping3 --icmp -d 65000 --flood {target}",
            "Fragmented": "hping3 -f --flood -p 80 {target}"
        }

        target = st.session_state.hping3_stats.get("target", "TARGET_IP") or "TARGET_IP"

        for attack_name, cmd in commands.items():
            is_active = st.session_state.hping3_attack and attack_name in st.session_state.hping3_stats.get(
                "attack_type", "")
            border_color = "#ef4444" if is_active else "#3b82f6"
            bg_color = "#450a0a" if is_active else "#1e293b"
            status = "🔴 ACTIVE" if is_active else "⚪ READY"

            st.markdown(f"""
            <div style="background:{bg_color}; border-left:3px solid {border_color}; 
                        padding:10px; border-radius:6px; margin:6px 0;">
                <div style="color:#94a3b8; font-size:11px;">{status} | {attack_name}</div>
                <code style="color:#4ade80; font-size:12px;">{cmd.format(target=target)}</code>
            </div>
            """, unsafe_allow_html=True)

    with c2:
        st.markdown("### 🛡️ IPS Detection Rules Triggered")

        # Show flood-related alerts
        flood_alerts = [a for a in list(st.session_state.alerts)
                        if any(word in a.get("description", "").lower()
                               for word in ["flood", "hping3", "syn", "icmp", "udp flood", "dos"])]

        if flood_alerts:
            for alert in flood_alerts[-10:][::-1]:
                level_color = "#ef4444" if alert["level"] >= 12 else "#f97316"
                st.markdown(f"""
                <div style="background:#1e293b; border-left:3px solid {level_color}; 
                            padding:10px; border-radius:6px; margin:6px 0;">
                    <div style="display:flex; justify-content:space-between;">
                        <span style="color:{level_color}; font-weight:600; font-size:13px;">
                            ⚠️ {alert.get('technique', 'Unknown')}
                        </span>
                        <span style="color:#94a3b8; font-size:11px;">
                            Level {alert['level']} | {alert['timestamp'].strftime('%H:%M:%S')}
                        </span>
                    </div>
                    <div style="color:#e2e8f0; font-size:12px; margin-top:4px;">
                        {alert.get('description', '')[:100]}
                    </div>
                    <div style="color:#64748b; font-size:11px; margin-top:4px;">
                        From: {alert.get('src', 'N/A')} → {alert.get('dst', 'N/A')}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No flood alerts triggered yet. Launch an attack simulation!")

        st.markdown("### 📊 Real-time Attack Metrics")

        # SYN counter chart
        if st.session_state.conn_tracker:
            top_attackers = sorted(
                [(ip, count) for ip, count in st.session_state.conn_tracker.items()
                 if not ip.startswith("udp_") and not ip.startswith("icmp_")],
                key=lambda x: x[1], reverse=True
            )[:10]

            if top_attackers:
                df_attack = pd.DataFrame(top_attackers, columns=["Source IP", "SYN Count"])
                df_attack["Status"] = df_attack["Source IP"].apply(
                    lambda x: "🚫 BLOCKED" if x in st.session_state.blocked_ips else "⚠️ ACTIVE"
                )

                fig = px.bar(df_attack, x="SYN Count", y="Source IP", orientation='h',
                             color="SYN Count", color_continuous_scale="Reds",
                             title="Top Attack Sources (SYN Count)")
                fig.update_layout(height=250, margin=dict(l=0, r=0, t=30, b=0),
                                  plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
                                  font=dict(color="white"))
                st.plotly_chart(fig, use_container_width=True)

# ================== ACTIVE BLOCKS TAB ==================
with tab_blocks:
    st.markdown("## 🚫 Active Blocks & IPS Response")

    # Block summary
    col1, col2, col3, col4 = st.columns(4)

    auto_blocks = sum(1 for b in st.session_state.active_blocks if b.get("block_type") in ["AUTO", "AUTO-IPS"])
    manual_blocks = sum(1 for b in st.session_state.active_blocks if b.get("block_type") == "MANUAL")

    with col1:
        st.markdown(metric_card("🚫 Total Blocked", len(st.session_state.blocked_ips), "red"), unsafe_allow_html=True)
    with col2:
        st.markdown(metric_card("🤖 Auto-Blocked", auto_blocks, "orange", "By IPS"), unsafe_allow_html=True)
    with col3:
        st.markdown(metric_card("👤 Manual Blocks", manual_blocks, "blue", "By Analyst"), unsafe_allow_html=True)
    with col4:
        st.markdown(metric_card("✅ Protected IPs", len(st.session_state.os_detections), "green", "Endpoints"),
                    unsafe_allow_html=True)

    st.markdown("---")

    c1, c2 = st.columns([2, 1])

    with c1:
        st.markdown("### 🚫 Active Block Rules")

        if not st.session_state.active_blocks:
            st.info("No active blocks. Launch an attack simulation to see automatic blocking in action!")
        else:
            # Filter
            block_filter = st.selectbox("Filter", ["All", "AUTO", "AUTO-IPS", "MANUAL"])

            blocks_list = list(st.session_state.active_blocks)[::-1]
            if block_filter != "All":
                blocks_list = [b for b in blocks_list if b.get("block_type") == block_filter]

            for block in blocks_list[:20]:
                block_type = block.get("block_type", "UNKNOWN")
                type_color = "#ef4444" if "AUTO" in block_type else "#3b82f6"
                type_icon = "🤖" if "AUTO" in block_type else "👤"

                col_a, col_b = st.columns([4, 1])
                with col_a:
                    st.markdown(f"""
                    <div class="block-card">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div class="block-ip">🚫 {block['src_ip']}</div>
                            <span style="background:{type_color}20; color:{type_color}; 
                                        padding:2px 8px; border-radius:10px; font-size:11px;">
                                {type_icon} {block_type}
                            </span>
                        </div>
                        <div class="block-reason">⚠️ {block['reason']}</div>
                        <div class="block-reason" style="color:#94a3b8;">{block['details']}</div>
                        <div class="block-time">
                            🕐 Blocked at: {block['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} | 
                            ⏰ Expires: {block.get('expires', 'Never')} | 
                            📋 Rule: {block['rule_id']}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                with col_b:
                    if st.button("🔓 Unblock", key=f"unblock_tab_{block['src_ip']}_{block['rule_id']}",
                                 use_container_width=True):
                        st.session_state.blocked_ips.discard(block["src_ip"])
                        st.session_state.active_blocks = deque(
                            [b for b in st.session_state.active_blocks if b["rule_id"] != block["rule_id"]],
                            maxlen=500
                        )
                        st.rerun()

    with c2:
        st.markdown("### 📊 Block Statistics")

        if st.session_state.active_blocks:
            # Block type distribution
            block_types = defaultdict(int)
            for b in st.session_state.active_blocks:
                block_types[b.get("block_type", "UNKNOWN")] += 1

            fig = go.Figure(go.Pie(
                values=list(block_types.values()),
                labels=list(block_types.keys()),
                hole=0.6,
                marker=dict(colors=["#ef4444", "#f97316", "#3b82f6"])
            ))
            fig.update_layout(height=220, margin=dict(l=0, r=0, t=10, b=0),
                              paper_bgcolor="#1e293b", font=dict(color="white"),
                              title=dict(text="Block Types", font=dict(color="white")))
            st.plotly_chart(fig, use_container_width=True)

            # Reasons
            st.markdown("#### 📋 Block Reasons")
            reason_counts = defaultdict(int)
            for b in st.session_state.active_blocks:
                reason_counts[b["reason"][:30]] += 1

            for reason, count in sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                st.markdown(f"""
                <div style="background:#1e293b; padding:8px; border-radius:6px; margin:4px 0;
                            border-left:3px solid #ef4444;">
                    <div style="color:#e2e8f0; font-size:12px;">{reason}</div>
                    <div style="color:#ef4444; font-weight:600;">{count} blocks</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("#### 🛡️ IPS Rules Active")
        ips_rules = [
            {"rule": "R-001", "name": "SYN Flood", "threshold": "50 SYN/s", "action": "AUTO BLOCK"},
            {"rule": "R-002", "name": "UDP Flood", "threshold": "100 UDP/s", "action": "AUTO BLOCK"},
            {"rule": "R-003", "name": "ICMP Flood", "threshold": "50 ICMP/s", "action": "AUTO BLOCK"},
            {"rule": "R-004", "name": "Port Scan", "threshold": "20 ports", "action": "ALERT"},
            {"rule": "R-005", "name": "DNS Tunnel", "threshold": ">50 chars", "action": "ALERT"},
        ]

        for rule in ips_rules:
            st.markdown(f"""
            <div style="background:#0f172a; padding:8px; border-radius:6px; margin:4px 0;
                        border-left:3px solid #10b981;">
                <div style="display:flex; justify-content:space-between;">
                    <span style="color:#4ade80; font-size:11px;">{rule['rule']}</span>
                    <span style="color:#f59e0b; font-size:11px;">{rule['action']}</span>
                </div>
                <div style="color:#e2e8f0; font-size:12px;">{rule['name']}</div>
                <div style="color:#64748b; font-size:11px;">Threshold: {rule['threshold']}</div>
            </div>
            """, unsafe_allow_html=True)

        # Export blocks
        if st.session_state.active_blocks:
            st.markdown("---")
            df_blocks = pd.DataFrame(list(st.session_state.active_blocks))
            csv = df_blocks.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Export Blocks", csv, "active_blocks.csv", "text/csv",
                               use_container_width=True)

# ================== EVENTS TAB ==================
with tab_events:
    st.markdown("### 📋 All Network Events")

    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        evt_search = st.text_input("🔍 Search events", placeholder="IP, protocol, port...")
    with c2:
        proto_filter = st.selectbox("Protocol", ["All", "TCP", "UDP", "ICMP", "ARP", "DNS"])
    with c3:
        show_blocked = st.checkbox("Show blocked only", value=False)

    if len(st.session_state.packets) > 0:
        df = pd.DataFrame(list(st.session_state.packets)[-500:][::-1])

        if evt_search:
            mask = df.astype(str).apply(lambda x: x.str.contains(evt_search, case=False)).any(axis=1)
            df = df[mask]
        if proto_filter != "All":
            df = df[df["proto"] == proto_filter]
        if show_blocked and st.session_state.blocked_ips:
            df = df[df["src"].isin(st.session_state.blocked_ips)]

        # Add blocked status
        df["blocked"] = df["src"].apply(lambda x: "🚫" if x in st.session_state.blocked_ips else "✅")

        st.dataframe(df, use_container_width=True, hide_index=True, height=600)
        st.caption(f"Showing {len(df)} events (max 500 most recent)")
    else:
        st.info("No events captured yet. Start capture from the sidebar.")

# ================== ALERTS TAB ==================
with tab_alerts:
    st.markdown("### 🚨 All Security Alerts")

    if len(st.session_state.alerts) > 0:
        c1, c2, c3 = st.columns([1, 1, 2])
        with c1:
            lvl = st.slider("Min Level", 0, 15, 0)
        with c2:
            tactic_filter = st.selectbox("Tactic", ["All"] + list(set(
                a.get("tactic", "") for a in st.session_state.alerts)))
        with c3:
            alert_search = st.text_input("🔍 Search alerts", placeholder="IP, technique, description...")

        df = pd.DataFrame(list(st.session_state.alerts)[::-1])
        df = df[df["level"] >= lvl]

        if tactic_filter != "All":
            df = df[df["tactic"] == tactic_filter]
        if alert_search:
            mask = df.astype(str).apply(lambda x: x.str.contains(alert_search, case=False)).any(axis=1)
            df = df[mask]

        st.dataframe(df, use_container_width=True, hide_index=True, height=600)

        # Stats
        c1, c2 = st.columns(2)
        with c1:
            if len(df) > 0 and "tactic" in df.columns:
                tactic_counts = df["tactic"].value_counts()
                fig = px.bar(tactic_counts, title="Alerts by Tactic",
                             color_discrete_sequence=["#ef4444"])
                fig.update_layout(height=300, plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
                                  font=dict(color="white"))
                st.plotly_chart(fig, use_container_width=True)
        with c2:
            if len(df) > 0 and "level" in df.columns:
                level_counts = df["level"].value_counts()
                fig = px.pie(values=level_counts.values, names=level_counts.index,
                             title="Alert Level Distribution", hole=0.5)
                fig.update_layout(height=300, paper_bgcolor="#1e293b", font=dict(color="white"))
                st.plotly_chart(fig, use_container_width=True)

        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("⬇️ Download Alerts CSV", csv, "alerts.csv", "text/csv")
    else:
        st.info("No alerts yet. Start capture to detect threats.")

# ================== PACKETS TAB ==================
with tab_packets:
    st.markdown("### 📦 Live Packet Capture")

    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown(f"**Total captured:** {len(st.session_state.packets):,} packets | "
                    f"**Blocked sources:** {len(st.session_state.blocked_ips)}")
    with col2:
        pkt_proto = st.selectbox("Protocol Filter", ["All", "TCP", "UDP", "ICMP", "ARP"], key="pkt_proto")
    with col3:
        show_only_flagged = st.checkbox("Blocked IPs only", key="pkt_blocked")

    if len(st.session_state.packets) > 0:
        df = pd.DataFrame(list(st.session_state.packets)[-200:][::-1])

        if pkt_proto != "All":
            df = df[df["proto"] == pkt_proto]
        if show_only_flagged and st.session_state.blocked_ips:
            df = df[df["src"].isin(st.session_state.blocked_ips)]

        # Highlight blocked IPs
        df["⚠️"] = df["src"].apply(lambda x: "🚫 BLOCKED" if x in st.session_state.blocked_ips else "")

        st.dataframe(df, use_container_width=True, hide_index=True, height=600)

        # Protocol chart
        if len(df) > 0:
            proto_counts = df["proto"].value_counts()
            fig = px.bar(proto_counts, color_discrete_sequence=["#3b82f6"],
                         title="Packet Protocol Distribution")
            fig.update_layout(height=250, plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
                              font=dict(color="white"))
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Start capture from the sidebar to see live packets.")

        # Show hping3 attack info
        st.markdown("### 💡 Quick Start")
        st.markdown("""
        1. Click **▶️ Start** in the sidebar to begin capture
        2. Use **💥 Launch** to simulate hping3 attacks
        3. Watch the **Dashboard** for real-time detection
        4. Check **Active Blocks** for IPS responses
        5. View **Endpoint OS** for fingerprinting results
        """)

# ---- Auto-refresh ----
if auto_refresh and st.session_state.capture_running:
    time.sleep(refresh_rate)
    st.rerun()