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

load = [0,0,0]

class LoadBalancer():
	def __init__(self):
		core.openflow.addListeners(self)
		self.host_location = {}
		self.host_ip_mac = {}
		self.max_hosts = 5

    def _handle_PacketIn(self,event):
        pass
	
    def _handle_FlowStatsReceived(self, event):
		pass

def launch():
	core.registerNew(LoadBalancer)
