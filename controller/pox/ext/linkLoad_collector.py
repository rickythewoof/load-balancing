import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.util import dpidToStr

class trafficMeter():

	def __init__(self, ip_src, ip_dst, time_period, dpid):
		self.src = ip_src
		self.dst = ip_dst
		self.traffic = 0
		self.time_period = time_period
		self.dpid = dpid
		self.connection = None
		core.openflow.addListeners(self)

	def _handle_ConnectionUp (self, event):
		# if the connecting switch has the DPID reported in self.dpid, then
		# save the connection object in self.connection
		# run the launch_component method

	def launch_component(self):
		Timer(self.time_period, self.send_stat_req, recurring=True)

	def _handle_FlowStatsReceived(self, event):
		rec_bytes = 0
		# sum the traffic stats of all the flow rules related to IP traffic from self.src to self.dst
		rate = (rec_bytes - self.traffic) / self.time_period
		self.traffic = rec_bytes
		print("IP flow rate: " + str(rate))

	def send_stat_req(self):
		# send a stat request OFP message to the switch

def launch(ip_src = "10.0.0.1", ip_dst = "10.0.0.2", time_period = 2, dpid = "7a-c4-ae-1c-40-46"):
	trafficMeter(ip_src, ip_dst, time_period, dpid)
