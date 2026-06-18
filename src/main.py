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
    parse_icmp_packet
)

# ---------------- ARG PARSER ----------------
def get_args():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("--tcp", action="store_true", help="show only TCP traffic")
    parser.add_argument("--udp", action="store_true", help="show only UDP traffic")
    return parser.parse_args()

# ---------------- LOCAL IP ----------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

# ---------------- DIRECTION ----------------
def get_direction(src_ip, dst_ip, local_ip):
    if src_ip == local_ip:
        return "OUT"
    elif dst_ip == local_ip:
        return "IN"
    else:
        return "OTHER"

# ---------------- DNS RESOLVE ----------------
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

# ---------------- MAIN ----------------
def main():
    args = get_args()

    sniffer = create_sniffer()
    local_ip = get_local_ip()

    print(f"Local IP: {local_ip}")
    print("Sniffer running...\n")

    log_file = open("traffic.log", "a")
    log_file.write("\n" + "=" * 50 + "\n")
    log_file.write(f"Sniffer started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_file.write("=" * 50 + "\n")
    log_file.flush()

    def log_packet(text):
        log_file.write(text + "\n")
        log_file.flush()

    # counters
    total_packets = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    other_count = 0

    # analytics
    top_sources = Counter()
    top_destinations = Counter()
    top_ports = Counter()

    last_print = time.time()

    # ---------------- LOOP ----------------
    while True:
        raw_data, addr = sniffer.recvfrom(65535)
        total_packets += 1

        eth = parse_ethernet_frame(raw_data)

        if eth["protocol"] != 2048:
            continue

        ip = parse_ipv4_packet(eth["payload"])

        top_sources[ip["source_ip"]] += 1
        top_destinations[ip["destination_ip"]] += 1

        direction = get_direction(
            ip["source_ip"],
            ip["destination_ip"],
            local_ip
        )

        # ---------------- TCP ----------------
        if ip["protocol"] == 6:

            if args.udp:
                continue

            tcp_count += 1

            tcp = parse_tcp_segment(ip["payload"])
            service = get_service_name(tcp["destination_port"])

            top_ports[tcp["destination_port"]] += 1

            hostname = resolve_hostname(ip["destination_ip"])

            log_entry = (
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"{direction} {service} TCP "
                f"{ip['source_ip']}:{tcp['source_port']} "
                f"→ {ip['destination_ip']} ({hostname}):{tcp['destination_port']}"
            )

            print(log_entry)
            log_packet(log_entry)

        # ---------------- UDP ----------------
        elif ip["protocol"] == 17:

            if args.tcp:
                continue

            udp_count += 1

            udp = parse_udp_segment(ip["payload"])
            service = get_service_name(udp["destination_port"])

            top_ports[udp["destination_port"]] += 1

            hostname = resolve_hostname(ip["destination_ip"])

            log_entry = (
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"{direction} {service} UDP "
                f"{ip['source_ip']}:{udp['source_port']} "
                f"→ {ip['destination_ip']} ({hostname}):{udp['destination_port']}"
            )

            print(log_entry)
            log_packet(log_entry)

        # ---------------- ICMP ----------------
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
                f"{direction} {icmp_name} "
                f"{ip['source_ip']} → {ip['destination_ip']} ({hostname})"
            )

            print(log_entry)
            log_packet(log_entry)

        # ---------------- OTHER ----------------
        else:
            other_count += 1

        # ---------------- STATS ----------------
        if time.time() - last_print >= 5:
            print("\n--- STATS ---")
            print(f"Total packets: {total_packets}")
            print(f"TCP: {tcp_count}")
            print(f"UDP: {udp_count}")
            print(f"ICMP: {icmp_count}")
            print(f"OTHER: {other_count}")
            print("-------------\n")

            print("\nTop Source IPs:")
            for ip_addr, count in top_sources.most_common(5):
                print(f"  {ip_addr}: {count}")

            print("\nTop Destination IPs:")
            for ip_addr, count in top_destinations.most_common(5):
                print(f"  {ip_addr}: {count}")

            print("\nTop Ports:")
            for port, count in top_ports.most_common(5):
                service = get_service_name(port)
                print(f"  {service}: {count}")

            print("-------------\n")

            last_print = time.time()


if __name__ == "__main__":
    main()