#!/usr/bin/env python3
"""
packet_sniffer.py (timeout-capable)

Captures packets using Scapy and writes:
 - capture.pcap (PCAP file)
 - packet_sniff_report.txt (summary)
 - observed_ports.csv (best-effort list of observed ports)
 - protocols_bar.png (bar chart)

Usage:
  sudo python3 packet_sniffer.py --iface eth0 --count 100 --timeout 30

This will capture up to 100 packets OR stop after 30 seconds.
"""
import argparse
import collections
import csv
import os
from datetime import datetime
from scapy.all import sniff, rdpcap, PcapWriter
import matplotlib.pyplot as plt

def detect_protocol(pkt):
    try:
        if pkt.haslayer('TCP'):
            return 'TCP'
        if pkt.haslayer('UDP'):
            return 'UDP'
        if pkt.haslayer('ICMP'):
            return 'ICMP'
        if pkt.haslayer('ARP'):
            return 'ARP'
        if pkt.haslayer('IPv6'):
            return 'IPv6'
        return pkt.lastlayer().name
    except Exception:
        return 'OTHER'

def analyze_pcap(pcap_file, txt_out, csv_ports_out, chart_out):
    packets = rdpcap(pcap_file)
    proto_counts = collections.Counter()
    port_rows = []

    for pkt in packets:
        proto = detect_protocol(pkt)
        proto_counts[proto] += 1

        # collect observed TCP/UDP ports (best-effort)
        try:
            if pkt.haslayer('TCP'):
                sport = pkt['TCP'].sport
                dport = pkt['TCP'].dport
                src = pkt.getlayer('IP').src if pkt.haslayer('IP') else 'N/A'
                dst = pkt.getlayer('IP').dst if pkt.haslayer('IP') else 'N/A'
                port_rows.append((src, sport, 'tcp'))
                port_rows.append((dst, dport, 'tcp'))
            elif pkt.haslayer('UDP'):
                sport = pkt['UDP'].sport
                dport = pkt['UDP'].dport
                src = pkt.getlayer('IP').src if pkt.haslayer('IP') else 'N/A'
                dst = pkt.getlayer('IP').dst if pkt.haslayer('IP') else 'N/A'
                port_rows.append((src, sport, 'udp'))
                port_rows.append((dst, dport, 'udp'))
        except Exception:
            pass

    # Text report
    with open(txt_out, "w") as f:
        f.write("Packet Sniffing Report\n")
        f.write(f"Capture file: {pcap_file}\n")
        f.write(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("Protocol distribution (counts):\n")
        for proto, cnt in proto_counts.most_common():
            f.write(f" - {proto}: {cnt}\n")
        f.write("\nNotes:\n - Capture includes both directions; port CSV is observational, not a definitive service map.\n")

    # CSV of observed ports
    with open(csv_ports_out, "w", newline="") as csvf:
        w = csv.writer(csvf)
        w.writerow(["host_ip","port","protocol"])
        for row in port_rows:
            w.writerow(row)

    # Bar chart
    labels = list(proto_counts.keys())
    values = [proto_counts[k] for k in labels]
    if labels:
        plt.figure(figsize=(7,4))
        plt.bar(labels, values)
        plt.title("Protocol distribution (captured packets)")
        plt.xlabel("Protocol")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.savefig(chart_out)
        plt.close()

    return proto_counts, port_rows

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer (Scapy) with timeout")
    parser.add_argument("--iface", required=True, help="Interface to capture on (e.g., eth0)")
    parser.add_argument("--count", type=int, default=100, help="Number of packets to capture (max)")
    parser.add_argument("--timeout", type=int, default=30, help="Maximum seconds to wait before stopping capture")
    parser.add_argument("--outfile", default="capture.pcap", help="Output pcap filename")
    parser.add_argument("--txt", default="packet_sniff_report.txt", help="Text summary filename")
    parser.add_argument("--csv", default="observed_ports.csv", help="CSV of observed ports")
    parser.add_argument("--chart", default="protocols_bar.png", help="Protocol distribution chart")
    args = parser.parse_args()

    outdir = os.getcwd()
    print(f"[+] Working directory: {outdir}")
    print(f"[+] Capturing up to {args.count} packets on {args.iface} (or until {args.timeout} seconds) → {args.outfile}")

    writer = PcapWriter(args.outfile, append=False, sync=True)
    def _pkt_handler(pkt):
        writer.write(pkt)

    # sniff will stop when count reached OR timeout elapsed (whichever comes first)
    try:
        sniff(count=args.count, iface=args.iface, prn=_pkt_handler, timeout=args.timeout)
    except PermissionError:
        print("[!] Permission denied. Make sure to run the script with sudo.")
        return
    except OSError as e:
        print(f"[!] OS error during sniff: {e}")
        return
    finally:
        try:
            writer.close()
        except Exception:
            pass

    if not os.path.exists(args.outfile) or os.path.getsize(args.outfile) == 0:
        print("[!] No packets captured (empty pcap). Try generating traffic or use a different interface.")
        return

    print("[+] Capture complete. Analyzing...")
    proto_counts, port_rows = analyze_pcap(args.outfile, args.txt, args.csv, args.chart)
    print("[+] Analysis complete.")
    for k,v in proto_counts.items():
        print(f"  {k}: {v}")

    print(f"[+] Text report: {args.txt}")
    print(f"[+] CSV (observed ports): {args.csv}")
    print(f"[+] Chart image: {args.chart}")
    print("[+] Done.")

if __name__ == "__main__":
    main()
