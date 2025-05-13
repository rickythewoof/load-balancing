import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

EXT_GW_IP = IPAddr("10.0.0.1")
EXT_GW_MAC = EthAddr("00:00:00:00:00:01")
INT_GW_IP = IPAddr("192.168.0.1")
INT_GW_MAC = EthAddr("01:00:00:00:00:01")

log = core.getLogger()

class ArpResponder(object):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("modulo avviato con successo!\n")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if packet.type == ethernet.ARP_TYPE:
            arp_packet = packet.payload
            if arp_packet.opcode == arp.REQUEST:
                if  arp_packet.protodst == EXT_GW_IP:
                    arp_reply = arp()
                    arp_reply.hwtype = arp.HW_TYPE_ETHERNET
                    arp_reply.prototype = arp.PROTO_TYPE_IP
                    arp_reply.opcode = arp.REPLY
                    arp_reply.hwsrc = EXT_GW_MAC
                    arp_reply.hwdst = arp_packet.hwsrc
                    arp_reply.protosrc = EXT_GW_IP
                    arp_reply.protodst = arp_packet.protosrc

                    ether = ethernet()
                    ether.type = ethernet.ARP_TYPE
                    ether.src = EXT_GW_MAC
                    ether.dst = arp_packet.hwsrc
                    ether.payload = arp_reply

                    msg = of.ofp_packet_out()
                    msg.data = ether.pack()
                    msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
                    event.connection.send(msg)
                    log.info("ARP SPOOFING ESTERNO REALIZZATO")
                elif arp_packet.protodst == INT_GW_IP:
                    arp_reply = arp()
                    arp_reply.hwtype = arp.HW_TYPE_ETHERNET
                    arp_reply.prototype = arp.PROTO_TYPE_IP
                    arp_reply.opcode = arp.REPLY
                    arp_reply.hwsrc = INT_GW_MAC
                    arp_reply.hwdst = arp_packet.hwsrc
                    arp_reply.protosrc = INT_GW_IP
                    arp_reply.protodst = arp_packet.protosrc

                    ether = ethernet()
                    ether.type = ethernet.ARP_TYPE
                    ether.src = INT_GW_MAC
                    ether.dst = arp_packet.hwsrc
                    ether.payload = arp_reply

                    msg = of.ofp_packet_out()
                    msg.data = ether.pack()
                    msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
                    event.connection.send(msg)
                    log.info("ARP SPOOFING INTERNO REALIZZATO")
                else:
                    log.error("who is it for??")
                    return
            if arp_packet.opcode == arp.REPLY:
                no = core.LoadBalancer.servers_discovered
                no = no + 1
                core.LoadBalancer.servers_discovered = no
                core.LoadBalancer.servers[no] = {}
                core.LoadBalancer.servers[no]['ip'] = str(arp_packet.protosrc)
                core.LoadBalancer.servers[no]['mac'] = str(arp_packet.hwsrc)
                core.LoadBalancer.servers[no]['port'] = event.port
                log.info("added server = {}".format(core.LoadBalancer.servers[no]))


def launch():
    core.registerNew(ArpResponder)
    
