import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.lldp import lldp
from pox.lib.util import dpidToStr
import networkx as nx
import numpy as np

load = {}

class LoadBalancer():
	def __init__(self):
		core.openflow.addListeners(self)
		ip_service_match = of.ofp_match( ) 
		ip_service_match.nw_dst = "192.168.42.0/24" 
		self.load_per_srv = {}
		self.host_location = {}
		self.host_ip_mac = {}
		self.config_timer()
	
	def config_timer(self, recurrence = 3):
		Timer(recurrence, self.send_stat_req, recurring=True)
	
	def _handle_PacketIn(self,event):
		pass

	'''
		Load Balancing and flow analysis part
	'''
	def send_stat_req(self):
		self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

	def _handle_FlowStatsReceived(self, event):
		rec_bytes = 0
		for f in event.stats:
			if f.match.nw_src == self.src and f.match.nw_dst == self.dst:
				rec_bytes += f.byte_count
		rate = (rec_bytes - self.traffic) / self.time_period
		self.traffic = rec_bytes
		print("IP flow rate: " + str(rate))


def launch():
	core.registerNew(LoadBalancer)
