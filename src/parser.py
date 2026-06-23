import struct

# =========================================================
# HELPERS (format raw binary data into readable text)
# =========================================================

def format_mac(mac):
    """Convert MAC address bytes → human readable format"""
    return ':'.join('%02x' % b for b in mac)


def format_ip(addr):
    """Convert IP address bytes → dotted format"""
    return '.'.join(map(str, addr))


# =========================================================
# ETHERNET FRAME PARSER
# =========================================================
def parse_ethernet_frame(data):
    try:
        dest_mac, src_mac, proto = struct.unpack("!6s6sH", data[:14])

        return {
            "destination_mac": format_mac(dest_mac),
            "source_mac": format_mac(src_mac),
            "protocol": proto,
            "payload": data[14:]
        }

    except:
        return None


# =========================================================
# IPV4 PACKET PARSER
# =========================================================
def parse_ipv4_packet(data):
    try:
        version_header_length = data[0]

        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4

        ttl, proto, src, dst = struct.unpack(
            "!8x B B 2x 4s 4s",
            data[:20]
        )

        return {
            "version": version,
            "header_length": header_length,
            "ttl": ttl,
            "protocol": proto,
            "source_ip": format_ip(src),
            "destination_ip": format_ip(dst),
            "payload": data[header_length:]
        }

    except:
        return None


# =========================================================
# TCP SEGMENT PARSER
# =========================================================
def parse_tcp_segment(data):

    src_port, dst_port = struct.unpack("!HH", data[:4])

    offset = (data[12] >> 4) * 4
    flags = data[offset - 1]

    return {
        "source_port": src_port,
        "destination_port": dst_port,

        "fin": bool(flags & 0x01),
        "syn": bool(flags & 0x02),
        "rst": bool(flags & 0x04),
        "psh": bool(flags & 0x08),
        "ack": bool(flags & 0x10),
        "urg": bool(flags & 0x20),

        "payload": data[20:]
    }
 
# =========================================================
# UDP SEGMENT PARSER
# =========================================================
def parse_udp_segment(data):
    try:
        src_port, dst_port, length = struct.unpack("!HHH", data[:6])

        return {
            "source_port": src_port,
            "destination_port": dst_port,
            "length": length,
            "payload": data[8:]
        }

    except:
        return None


# =========================================================
# SERVICE NAME MAPPING (PORT → NAME)
# =========================================================
def get_service_name(port):
    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        22: "SSH",
        21: "FTP",
    }

    return common_ports.get(port, str(port))


# =========================================================
# ICMP PACKET PARSER
# =========================================================
def parse_icmp_packet(data):
    try:
        icmp_type, icmp_code, checksum = struct.unpack("!BBH", data[:4])

        return {
            "type": icmp_type,
            "code": icmp_code,
            "checksum": checksum,
            "payload": data[4:]
        }

    except:
        return None


# =========================================================
# DNS QUERY PARSER (simple version)
# =========================================================
def parse_dns_query(data):
    try:
        # DNS header is 12 bytes
        if len(data) < 12:
            return None

        domain_parts = []
        position = 12

        # read labels until we hit null byte
        while position < len(data):
            length = data[position]

            # end of domain name
            if length == 0:
                break

            # safety check (avoid garbage packets)
            if length > 63:
                return None

            position += 1

            label = data[position:position + length]

            try:
                domain_parts.append(label.decode())
            except:
                return None

            position += length

        return ".".join(domain_parts)

    except:
        return None