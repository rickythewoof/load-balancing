import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

VIRTUAL_GATEWAY_IP = IPAddr("10.0.0.1")
FAKE_GATEWAY_MAC = EthAddr("00:00:00:00:00:01")

log = core.getLogger()

class ArpResponder(object):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("modulo avviato con successo!\n")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if packet.type == ethernet.ARP_TYPE:
            arp_packet = packet.payload
            if arp_packet.opcode == arp.REQUEST and arp_packet.protodst == VIRTUAL_GATEWAY_IP:
                arp_reply = arp()
                arp_reply.hwtype = arp.HW_TYPE_ETHERNET
                arp_reply.prototype = arp.PROTO_TYPE_IP
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = FAKE_GATEWAY_MAC
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.protosrc = VIRTUAL_GATEWAY_IP
                arp_reply.protodst = arp_packet.protosrc

                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.src = FAKE_GATEWAY_MAC
                ether.dst = arp_packet.hwsrc
                ether.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
                event.connection.send(msg)
                log.info("ARP SPOOFING REALIZZATO")

def launch():
    core.registerNew(ArpResponder)
    
