#!/usr/bin/env python3
"""
nmap_multi_scan.py

Performs three Nmap scans against a target:
 - SYN scan (-sS)
 - TCP connect scan (-sT)
 - UDP quick scan (-sU --top-ports 100)

For each scan we save Nmap outputs with base names:
  syn_scan.*   tcp_connect_scan.*   udp_scan.*

Then parse the XML outputs and create:
 - scan_report.txt   (human readable consolidated report)
 - open_ports.csv    (CSV: host_ip,port,protocol,state,service,version,detected_by)

Usage (recommended):
  # Run using the virtualenv python as root (example)
  sudo /home/kali/venvs/nmapenv/bin/python3 ~/Desktop/day01/nmap_multi_scan.py 192.168.0.206

Notes:
 - SYN and UDP scans require root privileges (raw sockets).
 - Adjust scan args (timing, ports) if target rate-limits or takes too long.
"""

import sys
import subprocess
import xml.etree.ElementTree as ET
import csv
from datetime import datetime
import os

# --------------------------
# Helper: run a system nmap call with -oA base_name
# --------------------------
def run_nmap_scan(base_name, target, args_list):
    """
    Run: nmap <args_list> -oA <base_name> <target>
    Produces: base_name.nmap, base_name.xml, base_name.gnmap
    Returns path to XML file (base_name.xml)
    """
    cmd = ["nmap"] + args_list + ["-oA", base_name, target]
    print(f"[+] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] nmap failed for {base_name}: {e}")
        return None
    xml_path = base_name + ".xml"
    if not os.path.exists(xml_path):
        print(f"[!] Expected XML {xml_path} not found.")
        return None
    return xml_path

# --------------------------
# Helper: parse nmap XML and return list of dicts for ports
# --------------------------
def parse_nmap_xml(xml_path, detected_by_label):
    """
    Parse the nmap XML and return list of dictionaries:
    { host, port, protocol, state, service, version, detected_by }
    """
    results = []
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for host in root.findall("host"):
        # get host IP (prefer address with addrtype='ipv4' or first address)
        host_ip = "N/A"
        for addr in host.findall("address"):
            addrtype = addr.get("addrtype","")
            if addrtype in ("ipv4","ipv6"):
                host_ip = addr.get("addr")
                break
        status = host.find("status")
        host_state = status.get("state") if status is not None else "unknown"

        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            portid = port.get("portid")
            protocol = port.get("protocol")
            state_elem = port.find("state")
            state = state_elem.get("state") if state_elem is not None else ""
            svc_elem = port.find("service")
            service = svc_elem.get("name") if svc_elem is not None else ""
            # build version string if present
            version_parts = []
            if svc_elem is not None:
                for k in ("product","version","extrainfo"):
                    v = svc_elem.get(k)
                    if v:
                        version_parts.append(v)
            version = " ".join(version_parts).strip()
            results.append({
                "host": host_ip,
                "port": int(portid),
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
                "detected_by": detected_by_label
            })
    return results

# --------------------------
# Main routine
# --------------------------
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 nmap_multi_scan.py <target_ip_or_hostname>")
        sys.exit(1)

    target = sys.argv[1]
    out_dir = os.getcwd()  # outputs will be created in current directory
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[+] Starting multi-scan against {target} at {ts}")
    all_results = []  # list of dicts for all discovered ports

    # 1) SYN scan (requires root for -sS)
    syn_base = os.path.join(out_dir, "syn_scan")
    syn_args = ["-sS", "-p-", "-T4", "-sV"]   # all ports, service detection
    syn_xml = run_nmap_scan(syn_base, target, syn_args)
    if syn_xml:
        syn_results = parse_nmap_xml(syn_xml, "SYN")
        all_results.extend(syn_results)

    # 2) TCP connect scan (-sT) as fallback
    tcp_base = os.path.join(out_dir, "tcp_connect_scan")
    tcp_args = ["-sT", "-p-", "-T4", "-sV"]
    tcp_xml = run_nmap_scan(tcp_base, target, tcp_args)
    if tcp_xml:
        tcp_results = parse_nmap_xml(tcp_xml, "TCP-CONNECT")
        all_results.extend(tcp_results)

    # 3) UDP quick scan (top 100 UDP ports) — can be slow; adjust if needed
    udp_base = os.path.join(out_dir, "udp_scan")
    udp_args = ["-sU", "--top-ports", "100", "-T3"]
    udp_xml = run_nmap_scan(udp_base, target, udp_args)
    if udp_xml:
        udp_results = parse_nmap_xml(udp_xml, "UDP-TOP100")
        all_results.extend(udp_results)

    # Aggregate results: combine duplicates (same host+port+proto) and merge detected_by
    agg = {}
    for r in all_results:
        key = (r["host"], r["port"], r["protocol"])
        if key not in agg:
            agg[key] = {
                "host": r["host"],
                "port": r["port"],
                "protocol": r["protocol"],
                "state": r["state"],
                "service": r["service"],
                "version": r["version"],
                "detected_by": set([r["detected_by"]])
            }
        else:
            # update state/service/version if missing, and add detected_by
            if not agg[key]["service"] and r["service"]:
                agg[key]["service"] = r["service"]
            if not agg[key]["version"] and r["version"]:
                agg[key]["version"] = r["version"]
            agg[key]["detected_by"].add(r["detected_by"])
            # prefer 'open' state if any of the scans reported open
            if r["state"] == "open":
                agg[key]["state"] = "open"

    # Write consolidated CSV and TXT report
    csv_path = os.path.join(out_dir, "open_ports.csv")
    txt_path = os.path.join(out_dir, "scan_report.txt")

    # CSV header: host_ip,port,protocol,state,service,version,detected_by
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["host_ip","port","protocol","state","service","version","detected_by"])
        for k in sorted(agg.keys(), key=lambda x: (x[0], x[1], x[2])):
            v = agg[k]
            writer.writerow([
                v["host"],
                v["port"],
                v["protocol"],
                v["state"],
                v["service"],
                v["version"],
                ",".join(sorted(v["detected_by"]))
            ])

    # TXT human report
    with open(txt_path, "w") as f:
        f.write("Nmap Multi-scan Report\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Timestamp: {ts}\n")
        f.write("\nScans performed and raw outputs:\n")
        f.write(f" - syn_scan.nmap / syn_scan.xml / syn_scan.gnmap\n")
        f.write(f" - tcp_connect_scan.nmap / tcp_connect_scan.xml / tcp_connect_scan.gnmap\n")
        f.write(f" - udp_scan.nmap / udp_scan.xml / udp_scan.gnmap\n\n")
        f.write("Discovered open/filtered ports (consolidated):\n\n")
        if not agg:
            f.write("No ports discovered in scans (target may be filtered or down).\n")
        else:
            f.write("| Host | Port | Proto | State | Service | Version | Detected by |\n")
            f.write("|------|------|-------|-------|---------|---------|-------------|\n")
            for k in sorted(agg.keys(), key=lambda x: (x[0], v["port"])):
                v = agg[k]
                f.write(f"| {v['host']} | {v['port']} | {v['protocol']} | {v['state']} | {v['service']} | {v['version']} | {','.join(sorted(v['detected_by']))} |\n")

        f.write("\nNotes:\n")
        f.write(" - 'Detected by' column lists which scans saw the port (SYN, TCP-CONNECT, UDP-TOP100).\n")
        f.write(" - Raw nmap output files (.nmap, .xml) are in this folder with the base names listed above.\n")
        f.write("\nScan complete.\n")

    print(f"[+] Wrote consolidated {csv_path} and {txt_path}")
    print("[+] Individual nmap raw outputs are present as syn_scan.*, tcp_connect_scan.*, udp_scan.*")

if __name__ == "__main__":
    main()
