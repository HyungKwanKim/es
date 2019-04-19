import socket

class UdpSender(object):
    def __init__(self, IP, PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        self.IP = IP
        self.PORT = PORT
    def send(self, msg):
        print('sending udp msg...', msg)
        if isinstance(msg, bytes):
            self.sock.sendto(msg, (self.IP, self.PORT))
        else:
            self.sock.sendto(bytes(msg, "utf-8"), (self.IP, self.PORT))

