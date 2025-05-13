from scapy.all import *
from threading import Thread

def send_pacchetto():
    frame = Ether(dst="00:00:00:00:00:01")/IP(src="10.0.0.2",dst="10.0.0.1")
    sendp(frame, iface="eth0")

def stampa_cattura():
    sniff(count=1, iface="eth0", prn=lambda x: x.show(), timeout=5)

P1 = Thread(target = send_pacchetto)
P2 = Thread(target = stampa_cattura)

P2.start()
P1.start()
print("\n")
P2.join()
P1.join()
