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
            service = get_service_name(tcp["destination_port"])

            top_ports[tcp["destination_port"]] += 1
            # port scan detection script
            source_ip = ip["source_ip"]
            if source_ip not in port_scan_tracker:
                port_scan_tracker[source_ip] = {
                    "ports": set(),
                    "first_seen": current_time,
                    "alerted": False
                }
            # reset if tracking window expired
            if current_time - port_scan_tracker[source_ip]["first_seen"] > 30:
                port_scan_tracker[source_ip] = {
                    "ports": set(),
                    "first_seen": current_time,
                    "alerted": False
                }
            # adding current destination port 
            port_scan_tracker[source_ip]["ports"].add(
                tcp["destination_port"]
            )
            
            hostname = resolve_hostname(ip["destination_ip"])

            log_entry = (
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"{direction} TCP {service} "
                f"{ip['source_ip']}:{tcp['source_port']} "
                f"→ {ip['destination_ip']}:{tcp['destination_port']} ({hostname})"
            )

            print(log_entry)
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