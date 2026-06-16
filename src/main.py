import argparse
from sniffer import create_sniffer
from parser import (
    parse_ethernet_frame,
    parse_ipv4_packet,
    parse_tcp_segment,
    parse_udp_segment,
    get_service_name
)


def main():

    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument(
        "--tcp",
        action="store_true",
        help="Filter only TCP packets"
    
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Filter only UDP packets"
    )
    args = parser.parse_args()
    sniffer = create_sniffer()

    print("Packet sniffer started...")

    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        eth = parse_ethernet_frame(raw_data)

        # Only IPv4 packets
        if eth["protocol"] == 2048:

            ip = parse_ipv4_packet(eth["payload"])

            if args.tcp and ip["protocol"] != 6:
                continue
            if args.udp and ip["protocol"] != 17:
                continue

            # ICMP (ping)
            if ip["protocol"] == 1:
                print(
                    f"ICMP {ip['source_ip']} → {ip['destination_ip']}"
                )

            # TCP traffic
            elif ip["protocol"] == 6:
                tcp = parse_tcp_segment(ip["payload"])

                service = get_service_name(tcp["destination_port"])

                print(
                    f"{service} TCP "
                    f"{ip['source_ip']}:{tcp['source_port']} "
                    f"→ {ip['destination_ip']}:{tcp['destination_port']}"
                )

            # UDP traffic
            elif ip["protocol"] == 17:
                udp = parse_udp_segment(ip["payload"])

                service = get_service_name(udp["destination_port"])

                print(
                    f"{service} UDP "
                    f"{ip['source_ip']}:{udp['source_port']} "
                    f"→ {ip['destination_ip']}:{udp['destination_port']}"
                )

            # Other IP protocols
            else:
                print(
                    f"IP {ip['source_ip']} → {ip['destination_ip']} "
                    f"| Proto {ip['protocol']}"
                )

        # Non-IPv4 Ethernet frames
        else:
            print(
                f"Ethernet | {eth['source_mac']} → {eth['destination_mac']} "
                f"| Proto {eth['protocol']}"
            )


if __name__ == "__main__":
    main()