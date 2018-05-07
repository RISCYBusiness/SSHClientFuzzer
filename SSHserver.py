import SSHprotocol
import threading
import random
import struct
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
    
    def Timeout(self):
        start = time.time()
        self.event.wait()
        if self.TIMEOUT < (time.time() - start):
            print 'No response from client after this packet !!! : {}'.format(self.last_response)
            exit(0)
        self.event.clear()
    
    def __init__(self, BIND_IP='127.0.0.1', BIND_PORT=22, fuzzy=False):
        SSHprotocol.SSH_KEYX.__init__(self)
        self.fuzzy = fuzzy
        self.event = threading.Event()
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
        clientmsg = self.conn.recv(5) # read packet_length and random_padding header
        BINARY_PACKET_SIZE = struct.unpack('>I', clientmsg[0:4])[0] + int(clientmsg[4].encode('hex'), 16) # packet_length + random_padding
        while len(clientmsg) < BINARY_PACKET_SIZE-15:
           clientmsg += self.conn.recv(1024)
           time.sleep(0.1)
        return clientmsg
    
    def Send(self, payload):
        self.conn.send(payload)
        self.last_response = payload
        
    def Stop(self):
        self.serversock.close()
    
    def listen_with_timeout(self, byte_length=1024, ssh_binary_protocol=False):
        timeout_thread = threading.Thread(target=self.Timeout)
        timeout_thread.start()
        if ssh_binary_protocol:
            clientmsg = self.accept_binary_packet()
        else:
            clientmsg = self.conn.recv(byte_length)
        self.event.set()
        timeout_thread.join()
        return clientmsg
        
    def Listen_Handshake(self):
        clientmsg = self.listen_with_timeout()
        if not clientmsg.startswith('SSH-2.0-'):
            return False
        self.log(clientmsg, isClient=True)
        self.log(self.SSH_SERVER_NAME, isClient=False)
        self.Send(self.SSH_SERVER_NAME)
        return True

    def Key_Exchange(self):
        clientmsg = self.listen_with_timeout(ssh_binary_protocol=True)
        self.log(clientmsg, isClient=True)
        severity = .2
        if self.fuzzy:
            if random.randint(0, self.FUZZ_SEVERITY_WEIGHT) == 0: # occasionally fluxuate severity
                severity = random.random()
        self.Send(self.CraftKeyX(fuzzy=self.fuzzy, severity=severity))
    
    def Run(self):
        self.serversock.bind((self.BIND_IP, self.BIND_PORT))
        self.serversock.listen(self.ALLOWED_CONNECTIONS)
        self.conn, self.addr = self.serversock.accept()
        if not self.Listen_Handshake():
            print 'Unexpected Client Response'
            exit(-1)
        self.Key_Exchange()
       
def main():
    server = SSHServer()
    server.Run()

if __name__ == "__main__":
    main()