from sniffer import create_sniffer

def main():
    sniffer = create_sniffer()
    print("Packet sniffer started...")
    while True:
        raw_data, addr = sniffer.recvfrom(65535)
        print(f"Packet captured: {len(raw_data)} bytes")

if __name__ == "__main__":
    main()
    