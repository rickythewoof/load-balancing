import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpidToStr
import numpy as np
import networkx as nx

class Routing():

	def __init__(self):
		core.openflow.addListeners(self)
		self.host_location = {}
		self.host_ip_mac = {}
		self.max_hosts = 5

	def _handle_ConnectionUp(self, event):
		self.hostDiscovery(event.connection)

	def hostDiscovery(self, connection):
		for h in range(self.max_hosts):
			arp_req = arp()
			arp_req.hwsrc = EthAddr("00:00:00:00:11:11")
			arp_req.opcode = arp.REQUEST
			arp_req.protosrc = IPAddr("10.0." + str(h) + ".1")
			arp_req.protodst = IPAddr("10.0." + str(h) + ".100")
			ether = ethernet()
			ether.type = ethernet.ARP_TYPE
			ether.dst = EthAddr.BROADCAST
			ether.src = EthAddr("00:00:00:00:11:11")
			ether.payload = arp_req
			msg = of.ofp_packet_out()
			msg.data = ether.pack()
			msg.actions.append(of.ofp_action_output(port = 1))
			connection.send(msg)

	def _handle_PacketIn(self, event):
		eth_frame = event.parsed
		if eth_frame.type == ethernet.ARP_TYPE and eth_frame.dst == EthAddr("00:00:00:00:11:11"):
			arp_msg = eth_frame.payload
			if arp_msg.opcode == arp.REPLY:
				ip_host = arp_msg.protosrc.toStr()
				mac_host = arp_msg.hwsrc.toStr()
				dpid = dpidToStr(event.dpid)
				self.host_location[ip_host] = event.dpid
				self.host_ip_mac[ip_host] = mac_host
		elif eth_frame.type == ethernet.IP_TYPE:
			ip_pkt = eth_frame.payload
			ip_src = ip_pkt.srcip
			ip_dst = ip_pkt.dstip
			switch_src = self.host_location[ip_src.toStr()]
			switch_dst = self.host_location[ip_dst.toStr()]
			S = list(core.linkDiscovery.switch_id.keys())[list(core.linkDiscovery.switch_id.values()).index(switch_src)]
			D = list(core.linkDiscovery.switch_id.keys())[list(core.linkDiscovery.switch_id.values()).index(switch_dst)]
			graph = core.linkDiscovery.getGraph()
			path = nx.shortest_path(graph, S, D)
			print(path)

def launch():
	Routing()
