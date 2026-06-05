import socket
def create_sniffer():
    sniffer = socket.socket(socket.AF_INET,
     socket.SOCK_RAW,
    socket.ntohs(0x0003)
      )
    
    
    
    return sniffer



