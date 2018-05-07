import SSHserver
import subprocess
import signal
import time
import threading

proc = None
hLog = open('/tmp/ssh_out','w')
bind_ip = '127.0.0.1'
def run_client():
    global proc
    global hLog
    time.sleep(0.1)
    proc = subprocess.Popen("ssh 127.0.0.1", stdout=subprocess.PIPE, shell=True)
    hLog.write(proc.stdout.readline())
    
while 1:
    #proc = subprocess.Popen("\"/mnt/c/Program Files (x86)/PuTTY/putty.exe\" 127.0.0.1", stdout=subprocess.PIPE, shell=True)
    server = SSHserver.SSHserver(BIND_IP = bind_ip, fuzzy=True)
    threading.Thread(target=run_client).start()
    server.Run()
    server.Stop()
    proc.kill()
    
    
