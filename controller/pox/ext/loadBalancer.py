import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

EXT_GW_IP = IPAddr("10.0.0.1")
EXT_GW_MAC = EthAddr("00:00:00:00:00:01")
INT_GW_IP = IPAddr("192.168.0.1")
INT_GW_MAC = EthAddr("01:00:00:00:00:01")

class LoadBalancer():

	servers_discovered = 0
	servers = {}
	load = {}

	def __init__(self):
		core.openflow.addListeners(self)
		#self.config_timer()
	
	def config_timer(self, recurrence = 3):
		Timer(recurrence, self.send_stat_req, recurring=True)
	
	def _handle_PacketIn(self,event):
		pkt = event.parsed
		ip_pkt = pkt.find('ipv4')
		if not ip_pkt:
			log.warn("Not an IPv4 Packet, ignoring...")
			return
		
		log.info("Got IP packet\t{} -> {}".format(ip_pkt.srcip, ip_pkt.dstip))
		if ip_pkt.dstip == EXT_GW_IP: # Packet comes from the external net (not internal)
			srv_no = self.get_best_server()
			if srv_no is not None:
				ip_pkt.dstip = IPAddr(self.servers[srv_no]['ip'])

				eth = ethernet()
				eth.type = ethernet.IP_TYPE
				eth.src = pkt.src
				eth.dst = EthAddr(self.servers[srv_no]['mac'])
				eth.payload = ip_pkt
				
				msg = of.ofp_packet_out()
				msg.data = eth
				msg.actions.append(of.ofp_action_output(port = self.servers[srv_no]['port']))
				connection = event.connection
				connection.send(msg)
				log.info("packet redirected to {}".format(self.servers[srv_no]['ip']))
		else:	# It's a response, change the src to the public IP and send it back
			msg = of.ofp_packet_out()
			
			ip_pkt.srcip = EXT_GW_IP

			eth = ethernet()
			eth.src = EXT_GW_MAC
			eth.dst = pkt.dst
			eth.type = ethernet.IP_TYPE
			eth.payload = ip_pkt
			msg.data = eth
			msg.actions.append(of.ofp_action_output(port = 1 )) # Assumption: this is outside
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
		self.get_server_info(event, max_servers = 1)

	def get_server_info(self, event, max_servers):
		for s in range(1, max_servers +1):
			arp_req = arp()
			arp_req.hwsrc = INT_GW_MAC
			arp_req.opcode = arp.REQUEST
			arp_req.protosrc = INT_GW_IP
			arp_req.protodst = IPAddr("192.168." + str(s) + ".1")
			ether = ethernet()
			ether.type = ethernet.ARP_TYPE
			ether.dst = EthAddr.BROADCAST
			ether.src = INT_GW_MAC
			ether.payload = arp_req
			msg = of.ofp_packet_out()
			msg.data = ether.pack()
			msg.actions.append(of.ofp_action_output(port = 2))
			event.connection.send(msg)




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
	
	def get_best_server(self):
		for n in self.servers.keys():
			return n

def launch():
	core.registerNew(LoadBalancer)
