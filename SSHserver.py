import SSHprotocol
import threading
import random
import struct
import select
from riscy_fuzzer import FUZZ_STYLE
import socket
import time
import logger

class SSHserver(logger.logger, SSHprotocol.SSH_KEYX):
    SSH_SERVER_NAME = 'SSH-2.0-riscy_fuzzer\r\n'
    BIND_IP = '127.0.0.1'
    BIND_PORT = 22
    ALLOWED_CONNECTIONS = 1
    TIMEOUT = 5
    FUZZ_SEVERITY_WEIGHT = 4 # deviate from default severity

    
    def __init__(self, BIND_IP='127.0.0.1', BIND_PORT=22, fuzz_style=FUZZ_STYLE.NONE, fuzz_severity=0.0):
        SSHprotocol.SSH_KEYX.__init__(self)
        self.fuzz_style = fuzz_style # riscy_fuzzer member
        self.fuzz_severity = fuzz_severity # riscy_fuzzer member
        self.BIND_IP = BIND_IP
        self.BIND_PORT = BIND_PORT
        self.serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = None
        self.addr = None
        self.last_response = None
    
    def accept_binary_packet(self):
        """
        Listens for packet with expected SSH Binary Packet protocol
        """
        ready = select.select([self.conn], [], [], self.TIMEOUT)
        if not ready[0]:
            print '\nClient is stuck!...Here is last packet sent to it:\n{}'.format(self.last_response.encode('hex'))
        clientmsg = self.conn.recv(5) # read packet_length and random_padding header
        BINARY_PACKET_SIZE = struct.unpack('>I', clientmsg[0:4])[0] + int(clientmsg[4].encode('hex'), 16) # packet_length + random_padding
        while len(clientmsg) < BINARY_PACKET_SIZE-15:
           clientmsg += self.conn.recv(1024)
        return clientmsg
    
    def Send(self, payload):
        self.conn.send(payload)
        self.last_response = payload
        
    def Stop(self):
        self.serversock.close()

    def listen_with_timeout(self, ssh_binary_protocol=False):
        if ssh_binary_protocol:
            clientmsg = self.accept_binary_packet()
        else:
            ready = select.select([self.conn], [], [], 100)
            if not ready[0]:
                print 'Timeout waiting for client helo'
                exit(0)
            clientmsg = self.conn.recv(1024)
        return clientmsg
        
    def Listen_Handshake(self):
        print 'Waiting for Client\n'
        clientmsg = self.listen_with_timeout()
        if not clientmsg.startswith('SSH-2.0-'):
            return False
        self.log(clientmsg, isClient=True)
        self.Send(self.SSH_SERVER_NAME)
        self.log(self.SSH_SERVER_NAME, isClient=False)
        return True

    def Key_Exchange(self):
        clientmsg = self.listen_with_timeout(ssh_binary_protocol=True)
        self.log(clientmsg, isClient=True)
        self.Send(self.CraftKeyX())
        clientmsg = self.listen_with_timeout(ssh_binary_protocol=False)
        self.log(clientmsg, isClient=True)

    def Run(self):
        self.serversock.bind((self.BIND_IP, self.BIND_PORT))
        self.serversock.listen(self.ALLOWED_CONNECTIONS)
        self.conn, self.addr = self.serversock.accept()
        self.conn.setblocking(0)
        self.Key_Exchange()
        
       
def main():
    server = SSHServer()
    server.Run()

if __name__ == "__main__":
    main()