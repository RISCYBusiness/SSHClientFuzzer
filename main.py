import SSHserver
import subprocess
import signal
import time
from riscy_fuzzer import FUZZ_STYLE
import threading

proc = None
bind_ip = '127.0.0.1'
ssh_client = '/usr/bin/ssh 127.0.0.1'
#ssh_client = '\"C:\\Program Files (x86)\\PuTTY\\putty.exe\"' 
#ssh_client = ['"/mnt/c/Program Files (x86)/Bitvise SSH Client/BvSsh.exe" -host=127.0.0.1 -loginOnStartup']
#ssh_client = '\"/mnt/c/Program Files (x86)/PuTTY/putty.exe\" 127.0.0.1' 
#ssh_client = "\"/mnt/c/Program Files (x86)/Pragma/Clients/ssh.exe\" 127.0.0.1"

def main():
    while 1:
        server = SSHserver.SSHserver(BIND_IP = bind_ip, fuzz_style=FUZZ_STYLE.MUTATE, fuzz_severity=0.2)
        proc = subprocess.Popen(ssh_client, stdout=subprocess.PIPE, shell=True)
        
        server.Run()
        subprocess.call('/mnt/c/Windows/System32/taskkill.exe /F /IM ssh.exe', stdout=subprocess.PIPE, shell=True)
        server.Stop()

if __name__== "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit(0)