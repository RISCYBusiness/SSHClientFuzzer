import SSHserver
import subprocess
import signal
import time
import threading

proc = None
bind_ip = '127.0.0.1'
ssh_client = '/usr/bin/ssh'

def run_client():
    global proc
    global hLog
    time.sleep(0.1)
    proc = subprocess.Popen("{} {}".format(ssh_client, bind_ip), stdout=subprocess.PIPE, shell=True)

def main():
    while 1:
        server = SSHserver.SSHserver(BIND_IP = bind_ip, fuzzy=True)
        threading.Thread(target=run_client).start()
        server.Run()
        server.Stop()
        proc.kill()

if __name__== "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit(0)