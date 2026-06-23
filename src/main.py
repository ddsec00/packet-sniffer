import socket
import argparse
import time
from collections import Counter

from sniffer import create_sniffer
from parser import (
    parse_ethernet_frame,
    parse_ipv4_packet,
    parse_tcp_segment,
    parse_udp_segment,
    get_service_name,
    parse_icmp_packet,
    parse_dns_query
)

# =========================================================
# CLI OPTIONS (filter TCP / UDP traffic)
# =========================================================
def get_args():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("--tcp", action="store_true", help="show only TCP traffic")
    parser.add_argument("--udp", action="store_true", help="show only UDP traffic")
    return parser.parse_args()


# =========================================================
# GET LOCAL MACHINE IP (used to detect IN / OUT traffic)
# =========================================================
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


# =========================================================
# DETERMINE PACKET DIRECTION
# =========================================================
def get_direction(src_ip, dst_ip, local_ip):
    if src_ip == local_ip:
        return "OUT"
    elif dst_ip == local_ip:
        return "IN"
    else:
        return "OTHER"


# =========================================================
# OPTIONAL: resolve IP → hostname (best-effort)
# =========================================================
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


# =========================================================
# MAIN PROGRAM
# =========================================================
def main():
    args = get_args()

    sniffer = create_sniffer()
    local_ip = get_local_ip()

    print(f"Local IP: {local_ip}")
    print("Sniffer running...\n")

    # ---------------- LOG FILE ----------------
    log_file = open("traffic.log", "a")

    def log_packet(text):
        log_file.write(text + "\n")
        log_file.flush()

    # ---------------- STATISTICS ----------------
    total_packets = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    other_count = 0

    top_sources = Counter()
    top_destinations = Counter()
    top_ports = Counter()
    top_domains = Counter()
    # IDS feature: port scan detection
    port_scan_tracker = {}
    # IDS feature: SYN flood detection
    syn_flood_tracker = {}

    last_print = time.time()

    # =====================================================
    # MAIN PACKET LOOP
    # =====================================================
    while True:
        raw_data, addr = sniffer.recvfrom(65535)
        total_packets += 1

        eth = parse_ethernet_frame(raw_data)

        # Only IPv4 traffic
        if eth["protocol"] != 2048:
            continue

        ip = parse_ipv4_packet(eth["payload"])

        # track IP stats
        top_sources[ip["source_ip"]] += 1
        top_destinations[ip["destination_ip"]] += 1

        direction = get_direction(
            ip["source_ip"],
            ip["destination_ip"],
            local_ip
        )

        # =====================================================
        # TCP TRAFFIC
        # =====================================================
        if ip["protocol"] == 6:

            if args.udp:
                continue

            tcp_count += 1

            tcp = parse_tcp_segment(ip["payload"])
            # =====================================================
            # SYN FLOOD DETECTION
            # =====================================================
            if tcp["syn"] and not tcp["ack"] and direction == "IN":
                 source_ip = ip["source_ip"]
                 current_time = time.time()

                 if source_ip not in syn_flood_tracker:
                     syn_flood_tracker[source_ip] = {
                         "syn_count": 0,
                         "first_seen": current_time,
                         "alerted": False
                     }
                 tracker = syn_flood_tracker[source_ip]
                

                # reset window after 10 seconds
                 if current_time - tracker["first_seen"] > 10:
                    tracker["syn_count"] = 0
                    tracker["first_seen"] = current_time
                    tracker["alerted"] = False
                 tracker["syn_count"] += 1
                
                 if (
                    tracker["syn_count"] >= 100
                    and not tracker["alerted"]
                ):
                    alert_message = (
                        f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}]\n"
                        f"⚠ SYN FLOOD DETECTED\n"
                        f"Source: {source_ip}\n"
                        f"SYN Packets: {tracker['syn_count']}\n"
                        f"Window: 10 seconds\n"
                    )
                    print(alert_message)
                    log_packet(alert_message)
                    tracker["alerted"] = True
            if tcp["syn"]:
                print("TCP FLAG: SYN")

            if tcp["ack"]:
                print("TCP FLAG: ACK")

            if tcp["rst"]:
                print("TCP FLAG: RST")

            if tcp["fin"]:
                print("TCP FLAG: FIN")

            service = get_service_name(tcp["destination_port"])

            top_ports[tcp["destination_port"]] += 1
            # =====================================================
            # PORT SCAN DETECTION (IMPROVED IDS LOGIC)
            # -----------------------------------------------------
            if direction == "IN":
                source_ip = ip["source_ip"]
                current_time = time.time()

                # 1. initialize tracking structure if new IP
                if source_ip not in port_scan_tracker:
                    port_scan_tracker[source_ip] = {
                        "ports": set(),          # unique ports targeted
                        "attempts": 0,           # total attempts
                        "first_seen": current_time,
                        "alerted": False
                    }
                tracker = port_scan_tracker[source_ip]


                # 2. reset if 30-second window expired
                if current_time - tracker["first_seen"] > 30:
                    tracker["ports"] = set()
                    tracker["attempts"] = 0
                    tracker["first_seen"] = current_time
                    tracker["alerted"] = False


                # 3. update tracking data
                tracker["ports"].add(tcp["destination_port"])
                tracker["last_seen"] = current_time
                tracker["attempts"] += 1

                unique_ports = len(tracker["ports"])
                attempts = tracker["attempts"]

                # 4. compute scan behaviour logic
                scan_ratio = unique_ports / attempts if attempts > 0 else 0

                # 5. detection logic 
                if (
                    unique_ports >= 10 and      # scanned many ports
                    attempts >= 10 and         # enough activity
                    scan_ratio > 0.8 and       # mostly unique ports → scan pattern
                    not tracker["alerted"]     # prevent spam alerts
                ):
                    ports_list = sorted(tracker["ports"])

                    alert_message = (
                        f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}]\n"
                        f"⚠ PORT SCAN DETECTED\n"
                        f"Source: {source_ip}\n"
                        f"Ports: {ports_list}\n"
                        f"Unique Ports: {unique_ports}\n"
                        f"Attempts: {attempts}\n"
                        f"Ratio: {scan_ratio:.2f}\n"
                    )

                    print(alert_message)

                    log_packet(alert_message)

                    tracker["alerted"] = True
                    
                
                

                    
                

                

                        
                 
            

                
            
            hostname = resolve_hostname(ip["destination_ip"])

            log_entry = (
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"{direction} TCP {service} "
                f"{ip['source_ip']}:{tcp['source_port']} "
                f"→ {ip['destination_ip']}:{tcp['destination_port']} ({hostname})"
            )

            print(f"[{direction}] TCP {service} {ip['source_ip']}:{tcp['source_port']} → {ip['destination_ip']}:{tcp['destination_port']}")
            log_packet(log_entry)

        # =====================================================
        # UDP TRAFFIC (includes DNS detection)
        # =====================================================
        elif ip["protocol"] == 17:

            if args.tcp:
                continue

            udp_count += 1

            udp = parse_udp_segment(ip["payload"])

            top_ports[udp["destination_port"]] += 1
            hostname = resolve_hostname(ip["destination_ip"])

            # ---------------- DNS HANDLING ----------------
            if udp["destination_port"] == 53 or udp["source_port"] == 53:

                domain = parse_dns_query(udp["payload"])

                if domain:
                    top_domains[domain] += 1

                    log_dns = (
                        f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                        f"{direction} DNS "
                        f"{ip['source_ip']} → {ip['destination_ip']} "
                        f"QUERY: {domain}"
                    )

                    print(log_dns)
                    log_packet(log_dns)

            # normal UDP log
            log_entry = (
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"{direction} UDP {get_service_name(udp['destination_port'])} "
                f"{ip['source_ip']}:{udp['source_port']} "
                f"→ {ip['destination_ip']}:{udp['destination_port']} ({hostname})"
            )

            print(log_entry)
            log_packet(log_entry)

        # =====================================================
        # ICMP TRAFFIC (ping etc.)
        # =====================================================
        elif ip["protocol"] == 1:

            icmp_count += 1

            icmp = parse_icmp_packet(ip["payload"])

            if icmp["type"] == 8:
                icmp_name = "PING REQUEST"
            elif icmp["type"] == 0:
                icmp_name = "PING REPLY"
            else:
                icmp_name = f"ICMP TYPE {icmp['type']}"

            hostname = resolve_hostname(ip["destination_ip"])

            log_entry = (
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"{direction} ICMP {icmp_name} "
                f"{ip['source_ip']} → {ip['destination_ip']} ({hostname})"
            )

            print(log_entry)
            log_packet(log_entry)

        # =====================================================
        # UNKNOWN PROTOCOLS
        # =====================================================
        else:
            other_count += 1

        # =====================================================
        # STATS EVERY 5 SECONDS
        # =====================================================
        if time.time() - last_print >= 5:

            print("\n--- STATS ---")
            print(f"Total packets: {total_packets}")
            print(f"TCP: {tcp_count}")
            print(f"UDP: {udp_count}")
            print(f"ICMP: {icmp_count}")
            print(f"OTHER: {other_count}")

            print("\nTop Source IPs:")
            for ip_addr, count in top_sources.most_common(5):
                print(f"  {ip_addr}: {count}")

            print("\nTop Destination IPs:")
            for ip_addr, count in top_destinations.most_common(5):
                print(f"  {ip_addr}: {count}")

            print("\nTop Ports:")
            for port, count in top_ports.most_common(5):
                print(f"  {get_service_name(port)}: {count}")

            print("\nTop Domains:")
            for domain, count in top_domains.most_common(5):
                print(f"  {domain}: {count}")

            print("-------------\n")

            last_print = time.time()


# =========================================================
# ENTRY POINT
# =========================================================
if __name__ == "__main__":
    main()