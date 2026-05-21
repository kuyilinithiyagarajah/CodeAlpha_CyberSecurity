#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           NETWORK PACKET SNIFFER - CodeAlpha             ║
║               Internship Task 1 - Python                 ║
╚══════════════════════════════════════════════════════════╝
Author     : CodeAlpha Intern
Description: Captures and analyzes network packets in real-time
             with colorful terminal output and file logging.
Usage      : sudo python3 network_sniffer.py
"""

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
from datetime import datetime
import os
import sys

# ─────────────────────────────────────────
#  ANSI COLOR CODES
# ─────────────────────────────────────────
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_BLUE = "\033[44m"

# ─────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────
LOG_FILE    = "captured_packets.log"
PACKET_COUNT = 0
MAX_PAYLOAD  = 80  # max bytes to display from payload

# ─────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────
def print_banner():
    banner = f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        ███╗   ██╗███████╗████████╗    ███████╗███╗  ██╗     ║
║        ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝████╗ ██║     ║
║        ██╔██╗ ██║█████╗     ██║       ███████╗██╔██╗██║     ║
║        ██║╚██╗██║██╔══╝     ██║       ╚════██║██║╚████║     ║
║        ██║ ╚████║███████╗   ██║       ███████║██║ ╚███║     ║
║        ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚══╝    ║
║                                                              ║
║          🔍 Network Packet Sniffer — CodeAlpha              ║
║                   Internship Task 1                          ║
╚══════════════════════════════════════════════════════════════╝
{Color.RESET}"""
    print(banner)
    print(f"  {Color.GREEN}▶ Started   :{Color.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {Color.GREEN}▶ Log File  :{Color.RESET} {LOG_FILE}")
    print(f"  {Color.GREEN}▶ Press     :{Color.RESET} Ctrl+C to stop\n")
    print(f"  {Color.GRAY}{'─' * 62}{Color.RESET}\n")

# ─────────────────────────────────────────
#  PROTOCOL LABEL + COLOR
# ─────────────────────────────────────────
def get_proto_label(packet):
    if TCP in packet:
        port = packet[TCP].dport or packet[TCP].sport
        if port == 80:   return "HTTP",    Color.GREEN
        if port == 443:  return "HTTPS",   Color.CYAN
        if port == 21:   return "FTP",     Color.YELLOW
        if port == 22:   return "SSH",     Color.MAGENTA
        if port == 25 or port == 587: return "SMTP", Color.YELLOW
        if port == 53:   return "DNS/TCP", Color.BLUE
        return "TCP", Color.BLUE
    elif UDP in packet:
        if DNS in packet: return "DNS", Color.BLUE
        return "UDP", Color.YELLOW
    elif ICMP in packet:
        return "ICMP", Color.MAGENTA
    elif ARP in packet:
        return "ARP", Color.RED
    return "OTHER", Color.GRAY

# ─────────────────────────────────────────
#  LOG TO FILE
# ─────────────────────────────────────────
def log_packet(entry: str):
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

# ─────────────────────────────────────────
#  PACKET HANDLER
# ─────────────────────────────────────────
def process_packet(packet):
    global PACKET_COUNT
    PACKET_COUNT += 1

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto_name, proto_color = get_proto_label(packet)

    # ── IP Layer ──────────────────────────
    src_ip = dst_ip = "N/A"
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    # ── Port Info ─────────────────────────
    src_port = dst_port = ""
    if TCP in packet:
        src_port = f":{packet[TCP].sport}"
        dst_port = f":{packet[TCP].dport}"
        flags = packet[TCP].flags
        flag_str = f" [{Color.RED}FLAGS={flags}{proto_color}]" if flags else ""
    elif UDP in packet:
        src_port = f":{packet[UDP].sport}"
        dst_port = f":{packet[UDP].dport}"
        flag_str = ""
    else:
        flag_str = ""

    # ── Payload ───────────────────────────
    payload_str = ""
    if Raw in packet:
        raw = bytes(packet[Raw])[:MAX_PAYLOAD]
        try:
            decoded = raw.decode("utf-8", errors="replace").strip()
            if decoded:
                payload_str = f"\n    {Color.GRAY}Payload : {decoded[:MAX_PAYLOAD]}{Color.RESET}"
        except Exception:
            payload_str = f"\n    {Color.GRAY}Payload : {raw.hex()[:MAX_PAYLOAD]}{Color.RESET}"

    # ── DNS Info ──────────────────────────
    dns_str = ""
    if DNS in packet and packet[DNS].qd:
        try:
            qname = packet[DNS].qd.qname.decode()
            dns_str = f"\n    {Color.CYAN}DNS Query: {qname}{Color.RESET}"
        except Exception:
            pass

    # ── ARP Info ──────────────────────────
    arp_str = ""
    if ARP in packet:
        op = "Request" if packet[ARP].op == 1 else "Reply"
        arp_str = f"\n    {Color.RED}ARP {op} | HW Src: {packet[ARP].hwsrc} → HW Dst: {packet[ARP].hwdst}{Color.RESET}"

    # ── Terminal Output ───────────────────
    pkt_num  = f"{Color.GRAY}[{PACKET_COUNT:04d}]{Color.RESET}"
    ts_str   = f"{Color.GRAY}{timestamp}{Color.RESET}"
    proto_tag = f"{proto_color}{Color.BOLD}[{proto_name:<8}]{Color.RESET}"
    route    = (f"{Color.WHITE}{src_ip}{src_port}{Color.RESET}"
                f" {Color.YELLOW}→{Color.RESET} "
                f"{Color.WHITE}{dst_ip}{dst_port}{Color.RESET}")

    line = f"  {pkt_num} {ts_str}  {proto_tag}  {route}{flag_str}{dns_str}{arp_str}{payload_str}"
    print(line)

    # ── File Logging ──────────────────────
    log_entry = (
        f"[{PACKET_COUNT:04d}] {timestamp} | {proto_name:<8} | "
        f"{src_ip}{src_port} -> {dst_ip}{dst_port}"
    )
    if dns_str:
        log_entry += f" | DNS: {packet[DNS].qd.qname.decode() if packet[DNS].qd else ''}"
    if payload_str:
        log_entry += f" | Payload: {bytes(packet[Raw])[:MAX_PAYLOAD].decode('utf-8','replace').strip()}"
    log_packet(log_entry)

# ─────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────
def print_summary():
    print(f"\n\n  {Color.GRAY}{'─' * 62}{Color.RESET}")
    print(f"\n  {Color.CYAN}{Color.BOLD}📊 Session Summary{Color.RESET}")
    print(f"  {Color.GREEN}▶ Total Packets Captured : {Color.WHITE}{PACKET_COUNT}{Color.RESET}")
    print(f"  {Color.GREEN}▶ Log saved to           : {Color.WHITE}{LOG_FILE}{Color.RESET}")
    print(f"  {Color.GREEN}▶ Stopped at             : {Color.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}")
    print(f"\n  {Color.CYAN}Thanks for using Net-Sniffer | CodeAlpha Internship{Color.RESET}\n")

# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
def main():
    # Check for root privileges
    if os.geteuid() != 0:
        print(f"\n  {Color.RED}[!] ERROR: Run this script as root / sudo{Color.RESET}")
        print(f"  {Color.YELLOW}    Usage: sudo python3 network_sniffer.py{Color.RESET}\n")
        sys.exit(1)

    print_banner()

    # Write log header
    with open(LOG_FILE, "w") as f:
        f.write(f"Network Packet Sniffer Log — CodeAlpha Internship\n")
        f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n")

    try:
        print(f"  {Color.GREEN}[*] Sniffing started... waiting for packets{Color.RESET}\n")
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print_summary()
    except Exception as e:
        print(f"\n  {Color.RED}[!] Error: {e}{Color.RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
