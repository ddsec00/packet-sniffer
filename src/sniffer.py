import socket
def create_sniffer():
    sniffer = socket.socket(socket.AF_PACKET,
     socket.SOCK_RAW,
    socket.ntohs(0x0003)
      )
    
    
    
    return sniffer


