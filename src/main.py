from sniffer import create_sniffer
from parser import parse_ethernet_frame, parse_ipv4_packet


def main():
    sniffer = create_sniffer()

    print("Packet sniffer started...")

    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        eth = parse_ethernet_frame(raw_data)

        # Only IPv4 packets (0x0800 = 2048)
        if eth["protocol"] == 2048:
            ip = parse_ipv4_packet(eth["payload"])

            print(
                f"IP {ip['source_ip']} → {ip['destination_ip']} "
                f"| Proto: {ip['protocol']} | TTL: {ip['ttl']} | Size: {len(raw_data)}"
            )
        else:
            print(
                f"Ethernet | {eth['source_mac']} → {eth['destination_mac']} "
                f"| Proto: {eth['protocol']}"
            )


if __name__ == "__main__":
    main()