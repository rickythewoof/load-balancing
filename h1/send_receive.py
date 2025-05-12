from scapy.all import *
from threading import Thread

def send_pacchetto():
    frame = Ether(dst="11:22:33:44:55:66")/IP(src="10.0.0.2",dst="10.0.255.255")
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
