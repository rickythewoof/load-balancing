

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()

# Parametri di configurazione
VIRTUAL_IP = IPAddr("10.0.0.1")                      # IP fittizio per il bilanciamento
BACKEND_IP = IPAddr("192.168.2.3")                  # IP reale del server backend
BACKEND_MAC = EthAddr("00:00:00:00:00:02")           # MAC reale del server backend
BACKEND_PORT = 2                                     # Porta su cui è collegato il server

class SimpleLoadBalancer(object):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("SimpleLoadBalancer attivato")

    def _handle_ConnectionUp(self, event):
        """
        All'arrivo di una nuova connessione da uno switch, installa proattivamente
        una regola per inviare al controller tutti i pacchetti destinati al VIP.
        """
        log.info("Nuovo switch connesso: %s", event.dpid)
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = VIRTUAL_IP
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Quando arriva un pacchetto IP destinato all'IP virtuale,
        viene riscritto per puntare al vero server.
        """
        packet = event.parsed
        ip_packet = packet.find('ipv4')

        if not ip_packet or ip_packet.dstip != VIRTUAL_IP:
            return  # Ignora altri pacchetti

        log.info("Pacchetto IP per %s ricevuto da %s", VIRTUAL_IP, ip_packet.srcip)
        log.info("ridireziono il pacchetto verso il server backend meno carico!\n") 

        # Riscrive MAC e IP di destinazione
        eth = packet
        eth.dst = BACKEND_MAC
        ip_packet.dstip = BACKEND_IP

        # Costruisce e invia packet_out verso il backend
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=BACKEND_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

        log.info("Pacchetto inoltrato a %s (%s) sulla porta %s", BACKEND_IP, BACKEND_MAC, BACKEND_PORT)

def launch():
    core.registerNew(SimpleLoadBalancer)
