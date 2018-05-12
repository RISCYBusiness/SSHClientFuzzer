import socket
import struct
import os
import random
import string
import time
from riscy_fuzzer import riscy_fuzzer
from riscy_fuzzer import FUZZ_STYLE
import logger
            
            
# Binary Packet Protocol
class SSH_BinaryPacket(logger.logger, riscy_fuzzer):
    PACKET_ALIGNMENT = 8
    """
    SSH Transport Layer Protocol    2.0 rfc4253

      uint32    packet_length
      byte      padding_length
      byte[n1]  payload; n1 = packet_length - padding_length - 1
      byte[n2]  random padding; n2 = padding_length
      byte[m]   mac (Message Authentication Code - MAC); m = mac_length

      packet_length
         The length of the packet in bytes, not including 'mac' or the
         'packet_length' field itself.

      padding_length
         Length of 'random padding' (bytes).

      payload
         The useful contents of the packet.  If compression has been
         negotiated, this field is compressed.  Initially, compression
         MUST be "none".

      random padding
         Arbitrary-length padding, such that the total length of
         (packet_length || padding_length || payload || random padding)
         is a multiple of the cipher block size or 8, whichever is larger.  
         There MUST be at least four bytes of padding.  The
         padding SHOULD consist of random bytes.  The maximum amount of
         padding is 255 bytes.

      mac
         Message Authentication Code.  If message authentication has
         been negotiated, this field contains the MAC bytes.  Initially,
         the MAC algorithm MUST be "none".
    """
    def __init__(self):
        riscy_fuzzer.__init__(self)
        self.packet_blob = []
        self.packet_size = 0
        self.padding_length = 0
        self.payload = ''
        self.random_padding = 0

    def compute_padding_length(self, blob):
        raw_size = len(blob)
        return self.PACKET_ALIGNMENT - (raw_size % self.PACKET_ALIGNMENT)
        
    """
    Converts raw payload to SSH binary packet
    """
    def CraftBP(self, payload):
        
        self.payload = payload
        self.packet_blob.append(struct.pack(">i", 0)) # setup dummy length
        self.packet_blob.append(struct.pack(">b", 0)) # setup dummy padding length
        self.packet_blob.append(self.payload)
        self.padding_length = self.compute_padding_length("".join(self.packet_blob))
        self.packet_blob[1] = chr(self.padding_length)
        self.packet_size = struct.pack(">i", len("".join(self.packet_blob)) -2 )
        self.packet_blob[0] = self.packet_size
        self.packet_blob.append(
            "A"*self.padding_length # generate "random" padding
        ) 
        final_packet = "".join(self.packet_blob)
        print final_packet.encode('hex')
        #self.log("Raw Packet Bytes\n{}".format(final_packet.encode('hex')), isClient=False)
        return final_packet

# Key exchange protocol
class SSH_KEYX(SSH_BinaryPacket):
    """
    SSH Transport Layer Protocol    2.0  
      
      byte         SSH_MSG_KEXINIT
      byte[16]     cookie (random bytes)
      name-list    kex_algorithms
      name-list    server_host_key_algorithms
      name-list    encryption_algorithms_client_to_server
      name-list    encryption_algorithms_server_to_client
      name-list    mac_algorithms_client_to_server
      name-list    mac_algorithms_server_to_client
      name-list    compression_algorithms_client_to_server
      name-list    compression_algorithms_server_to_client
      name-list    languages_client_to_server
      name-list    languages_server_to_client
      boolean      first_kex_packet_follows
      uint32       0 (reserved for future extension)
    """    
    
    # Proper KeyX Server Response (OpenSSH_5.5 Debian)
    SSH_MSG_KEXINIT = '\x14'
    COOKIE = 'AAAAAAAAAAAAAAAA'
    KEX_ALGORITHMS = "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,rsa2048-sha256,rsa1024-sha1"
    SERVER_HOST_KEY_ALGORITHMS="ssh-rsa,ssh-dss"
    ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER="aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,arcfour256,arcfour128"
    ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT= "aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,arcfour256,arcfour128"
    MAC_ALGORITHMS_CLIENT_TO_SERVER="hmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5"
    MAC_ALGORITHMS_SERVER_TO_CLIENT="hmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5"
    COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER="none,zlib"
    COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT="none,zlib"
    LANGUAGES_CLIENT_TO_SERVER=""
    LANGUAGES_SERVER_TO_CLIENT=""
    FIRST_KEX_PACKET_FOLLOWS = False
    RESERVED = 0
    # / Proper KeyX Server Response
    
    def __init__(self):
        SSH_BinaryPacket.__init__(self)
        self.keyx_data = {
            'ssh_msg_keyxinit': self.SSH_MSG_KEXINIT,
            'cookie': self.COOKIE,
            'kex_algorithms': self.KEX_ALGORITHMS,
            'server_host_key_algorithms': self.SERVER_HOST_KEY_ALGORITHMS,
            'encryption_algorithms_client_to_server': self.ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER,
            'encryption_algorithms_server_to_client': self.ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT,
            'mac_algorithms_client_to_server': self.MAC_ALGORITHMS_CLIENT_TO_SERVER,
            'mac_algorithms_server_to_client': self.MAC_ALGORITHMS_SERVER_TO_CLIENT,
            'compression_algorithms_client_to_server': self.COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER,
            'compression_algorithms_server_to_client': self.COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT,
            'languages_client_to_server': self.LANGUAGES_CLIENT_TO_SERVER,
            'languages_server_to_client': self.LANGUAGES_SERVER_TO_CLIENT,
            'first_kex_packet_follows': self.FIRST_KEX_PACKET_FOLLOWS,
            'reserved': self.RESERVED
        }

    def FuzzParams(self):
        protocol_attributes = self.keyx_data.keys()
        iterations = int(self.fuzz_severity*len(protocol_attributes))
        if self.fuzz_style == FUZZ_STYLE.SNIPER:
            self.keyx_data = self.load_sniper_data()
            return
        for _ in range(0, iterations):
            index = self.keyx_data.keys()[random.randrange(0, len(protocol_attributes)-1)]
            if self.fuzz_style == FUZZ_STYLE.MUTATE:
                if isinstance(self.keyx_data[index], int):
                    self.keyx_data[index] = self.fuzz_int()
                    continue
                self.keyx_data[index] = self.mutate_str(self.keyx_data[index]) # Mutate
            elif self.fuzz_style == FUZZ_STYLE.BUFFER_BUSTER:
                self.keyx_data[index] = self.fuzz_str(random.randint(1,10)*100000)

    def CraftKeyX(self):
        packet = []
        
        if self.fuzz_style != FUZZ_STYLE.NONE:
            self.FuzzParams()
            
        if self.fuzz_style == FUZZ_STYLE.SNIPER: # sniper loads raw data, so no need packing it
            self.log(self.keyx_data, isClient=False)
            return self.keyx_data
        
        packet.append(self.keyx_data['ssh_msg_keyxinit'])
        packet.append(self.keyx_data['cookie'])
       
        packet.append(struct.pack(">I", len(self.keyx_data['kex_algorithms'])))
        packet.append(self.keyx_data['kex_algorithms'])

        packet.append(struct.pack(">I", len(self.keyx_data['server_host_key_algorithms'])))
        packet.append(self.keyx_data['server_host_key_algorithms'])

        packet.append(struct.pack(">I", len(self.keyx_data['encryption_algorithms_client_to_server'])))
        packet.append(self.keyx_data['encryption_algorithms_client_to_server'])

        packet.append(struct.pack(">I", len(self.keyx_data['encryption_algorithms_server_to_client'])))
        packet.append(self.keyx_data['encryption_algorithms_server_to_client'])

        packet.append(struct.pack(">I", len(self.keyx_data['mac_algorithms_client_to_server'])))
        packet.append(self.keyx_data['mac_algorithms_client_to_server'])

        packet.append(struct.pack(">I", len(self.keyx_data['mac_algorithms_server_to_client'])))
        packet.append(self.keyx_data['mac_algorithms_server_to_client'])

        packet.append(struct.pack(">I", len(self.keyx_data['compression_algorithms_client_to_server'])))
        packet.append(self.keyx_data['compression_algorithms_client_to_server'])

        packet.append(struct.pack(">I", len(self.keyx_data['compression_algorithms_server_to_client'])))
        packet.append(self.keyx_data['compression_algorithms_server_to_client'])

        packet.append(struct.pack(">I", len(self.keyx_data['languages_client_to_server'])))
        packet.append(self.keyx_data['languages_client_to_server'])

        packet.append(struct.pack(">I", len(self.keyx_data['languages_server_to_client'])))
        packet.append(self.keyx_data['languages_server_to_client'])
        try:
            packet.append(chr(self.keyx_data['first_kex_packet_follows']))
        except:
            packet.append(chr(random.randint(0,1)==0))
        try:
            packet.append(struct.pack(">I", int(self.keyx_data['reserved'])))
        except:
            packet.append(struct.pack(">I", 0))
            
        log_message =[ '----Crafted KeyX Response-----' ]
        for key in self.keyx_data.keys():
            log_message.append("-- {} : {}".format(key, self.keyx_data[key]))
        self.log("\n".join(log_message), isClient=False)
        return self.CraftBP("".join(packet)) # convert to SSH Binary packet (wraps payload)
