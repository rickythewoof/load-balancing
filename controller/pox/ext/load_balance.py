import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.lldp import lldp
from pox.lib.util import dpidToStr
import networkx as nx
import numpy as np

servers = {}
load = {}
public_ip = IpAddr("10.0.0.1")

class LoadBalancer():
	def __init__(self):
		core.openflow.addListeners(self)
		ip_service_match = of.ofp_match( ) 
		ip_service_match.nw_dst = public_ip 
		self.config_timer()
	
	def config_timer(self, recurrence = 3):
		Timer(recurrence, self.send_stat_req, recurring=True)
	
	def _handle_PacketIn(self,event):
		pkt = event.parsed
		if pkt.type == ethernet.ARP_TYPE 
			pass
		elif pkt.dst == public_ip: # Packet comes from the external net (not internal)
			best_server = self.find_best_server()
			if best_server is not None:
				src_port = event.port
				# Need to save the port from which the request came (maybe encode in MAC?)
				
				msg = of.ofp_packet_out()
				msg.data = ethernet()
				msg.src = pkt.src
				msg.dst = servers[best_server].ip
				msg.actions.append(of.ofp_action_output(port = servers[best_server]['port']))
				connection = event.connection
				connection.send(msg)
		else:	# It's a response, change the src to the public IP and send it back
			msg = of.ofp_packet_out()
			msg.data = ethernet()
			msg.src = public_ip
			msg.dst = pkt.dst
			msg.actions.append(of.ofp_action_output(port = Null )) # Get the port!
			connection = event.connection
			connection.send(msg)

	'''
		With a ConnectionUp we register the location of all servers
		We save:
			- DPID
			- Port
			- IP connection
			(I'd use servers dict, or overall class?)
			
		We create:
			- New entry on the load
			- New entry on the servers tab
	'''
	def _handle_ConnectionUp(self, event):
		self.create_flow_mod(event)

	def create_flow_mod(self, event):
		pass

	def create_server(self, event):
		pkt = event.parsed
		srv_dpid = pkt.dpid
		if srv_dpid in servers.keys():
			print("srv already there, skipping")
			return
		servers[srv_dpid] = {}
		servers[srv_dpid]["port"] = pkt.port
		servers[srv_dpid]["ip"] = Null # Get server IP
		servers[srv_dpid]["mac"] = Null # Get server MAC



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
	core.registerNew(passLoadBalancer)
