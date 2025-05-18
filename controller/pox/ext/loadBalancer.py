import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
import time

log = core.getLogger()

CLIENT_GW_IP = IPAddr("10.0.0.1")
CLIENT_GW_MAC = EthAddr("00:00:00:00:00:01")
SERVER_GW_IP = IPAddr("192.168.0.1")
SERVER_GW_MAC = EthAddr("01:00:00:00:00:01")

class LoadBalancer:
    def __init__(self):
        self.servers = {}          # id -> {ip, mac, port, capacity}
        self.conn_track = {}       # (client_ip, client_port, server_ip, server_port) -> client_mac
        self.next_server_id = 1
        self.load = {}
        core.openflow.addListeners(self)
        Timer(3, self.send_stats_request, recurring=True)

    def _handle_ConnectionUp(self, event):
        self.discover_servers(event, max_servers=10)

    def _handle_PacketIn(self, event):
        pkt = event.parsed
        # ARP handling
        arp_req = pkt.find(arp)
        if arp_req and arp_req.opcode == arp.REPLY:
            self.handle_arp_reply(arp_req, event.port)
            return

        ip_pkt = pkt.find(ipv4)
        tcp_pkt = pkt.find(tcp)
        # Only handle TCP over IPv4 ( Firewall Rule *wink wink* )
        if not ip_pkt or not tcp_pkt:
            return

        # From client to gateway: DNAT
        if ip_pkt.dstip == CLIENT_GW_IP:
            self.handle_client(event, ip_pkt, tcp_pkt)
            return

        # From server to client: SNAT
        if ip_pkt.srcip in [s['ip'] for s in self.servers.values()]:
            self.handle_server(event, ip_pkt, tcp_pkt)
            return

    def handle_arp_reply(self, arp_pkt, port):
        sid = self.next_server_id
        self.next_server_id += 1
        self.servers[sid] = {
            'ip': str(arp_pkt.protosrc),
            'mac': str(arp_pkt.hwsrc),
            'port': port,
            'capacity': 1000 #kbps
        }
        log.info(f"Server discovered #{sid}: {self.servers[sid]}")

    def handle_client(self, event, ip_pkt, tcp_pkt):
        # Choose a server based on load_balancing formula
        sid = self.select_server(ip_pkt, tcp_pkt)
        if sid is None:
            log.warn("No servers available (Shouldn't be possible, all requests are handled)")
            return

        server = self.servers[sid]
        
        # Connection tracking over conn_track
        key = (str(ip_pkt.srcip), tcp_pkt.srcport,
               server['ip'], tcp_pkt.dstport)
        self.conn_track[key] = event.parsed.src

        # Install flow for this client -> server connection
        match = of.ofp_match()
        match.dl_type = 0x0800
        match.nw_proto = 6
        match.nw_src = ip_pkt.srcip
        match.nw_dst = CLIENT_GW_IP
        match.tp_src = tcp_pkt.srcport
        match.tp_dst = tcp_pkt.dstport

        actions = [
            of.ofp_action_nw_addr.set_dst(IPAddr(server['ip'])),
            of.ofp_action_dl_addr.set_src(SERVER_GW_MAC),
            of.ofp_action_dl_addr.set_dst(EthAddr(server['mac'])),
            of.ofp_action_output(port=server['port'])
        ]

        self.install_flow(event, match, actions)

        # Rewrite destination
        ip_pkt.payload = tcp_pkt
        ip_pkt.dstip = IPAddr(server['ip'])
        # Build Ethernet frame
        eth = ethernet(type=ethernet.IP_TYPE,
                       src=SERVER_GW_MAC,
                       dst=EthAddr(server['mac']))
        eth.payload = ip_pkt

        # Send out
        msg = of.ofp_packet_out()
        try:
            msg.data=eth.pack()
        except Exception as e:
            log.error(f"[CHKSUM_ERROR] Caught exception: {e}")
            return
        msg.actions.append(of.ofp_action_output(port=server['port']))
        event.connection.send(msg)
        log.info(f"Forwarded client->server via {key}")


    def handle_server(self, event, ip_pkt, tcp_pkt):
        # Get our original client MAC
        key = (str(ip_pkt.dstip), tcp_pkt.dstport,
               str(ip_pkt.srcip), tcp_pkt.srcport)
        client_mac = self.conn_track.get(key)
        if not client_mac:
            log.warn(f"Connection not tracked: {key}")
            return
        
        # Install flow for this server -> client answer
        match = of.ofp_match()
        match.dl_type = 0x0800
        match.nw_proto = 6
        match.nw_src = ip_pkt.srcip
        match.nw_dst = ip_pkt.dstip
        match.tp_src = tcp_pkt.srcport
        match.tp_dst = tcp_pkt.dstport

        actions = [
            of.ofp_action_nw_addr.set_src(CLIENT_GW_IP),
            of.ofp_action_dl_addr.set_src(CLIENT_GW_MAC),
            of.ofp_action_dl_addr.set_dst(client_mac),
            of.ofp_action_output(port=1)
        ]
        self.install_flow(event, match, actions)

        # SNAT: rewrite source
        ip_pkt.payload = tcp_pkt
        ip_pkt.srcip = CLIENT_GW_IP
        # Build Ethernet
        eth = ethernet(type=ethernet.IP_TYPE,
                       src=CLIENT_GW_MAC,
                       dst=EthAddr(client_mac))
        eth.payload = ip_pkt

        # Send back to client (assumption: port 1)
        msg = of.ofp_packet_out()
        try:
            msg.data=eth.pack()
        except Exception as e:
            log.error(f"[CHKSUM_ERROR] Caught exception: {e}")
            return
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)
        # log.info(f"Forwarded server->client for {key}")

        # Drop RESET and FINISHED TCP connections
        # if tcp_pkt.flags & (tcp_pkt.FIN | tcp_pkt.RST):
        #     self.conn_track.pop(key, None)
        #     log.info(f"Cleaned up connection {key}")
            


    def select_server(self, ip_pkt, tcp_pkt):
        if not self.servers:
            return None
        # Return first of the non occupied servers
        ip_src = str(ip_pkt.srcip)
        port_src = tcp_pkt.srcport
        port_dst = tcp_pkt.dstport

        # check first if there is already a server with an active connection
        # to this client

        for key in self.conn_track:
            src_ip, src_port, srv_ip, dst_port = key
            if src_ip == ip_src and src_port == port_src and dst_port == port_dst:
                log.info("Already found an active connection")
                for server_id, server in self.servers.items():
                    if server['ip'] == srv_ip:
                        return server_id
        
        # Calculate load for every server and return the lightest
        val = {}
        for sid in self.servers:
            val[sid] = 0
            if self.load.get(sid):
                for vals in self.load[sid].values():
                    val[sid] = val[sid] + vals
            val[sid] = val[sid] / self.servers[sid]['capacity']
    
        log.info(f"load overall is {val}")

        min_load = None
        min_sid = None
        for sid, load in val.items():
            if min_load is None or load < min_load:
                min_load = load
                min_sid = sid

        return min_sid

    def discover_servers(self, event, max_servers):
        for i in range(1, max_servers + 1):
            arp_req = arp(hwsrc=SERVER_GW_MAC,
                          opcode=arp.REQUEST,
                          protosrc=SERVER_GW_IP,
                          protodst=IPAddr(f"192.168.{i}.1"))
            eth = ethernet(type=ethernet.ARP_TYPE,
                           src=SERVER_GW_MAC,
                           dst=EthAddr.BROADCAST)
            eth.payload = arp_req.pack()
            msg = of.ofp_packet_out(data=eth.pack())
            msg.actions.append(of.ofp_action_output(port=2))
            event.connection.send(msg)

    def send_stats_request(self):
        for con in core.openflow._connections.values():
            con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_FlowStatsReceived(self, event):
        self.load = {}
        for stat in event.stats:
            if stat.match.nw_src is None or "192.168" not in str(stat.match.nw_src):
                continue
            log.info(f"Src: {stat.match.nw_src}:{stat.match.tp_src} -> Dst: {stat.match.nw_dst}:{stat.match.tp_dst}, Bytes: {stat.byte_count}")
            # Get server ID from src_ip
            # Update the values for the services (port)
            for sid in self.servers:
                if self.servers[sid]['ip'] == str(stat.match.nw_src):
                    if self.load.get(sid) is None:
                        self.load[sid] = {}
                    self.load[sid][stat.match.tp_src] = stat.byte_count

    def install_flow(self, event, match, actions):
        msg = of.ofp_flow_mod()
        msg.priority = 5000
        msg.idle_timeout = 5 #  Tune timeout to not flood requests
        msg.match = match
        msg.actions = actions
        event.connection.send(msg)

def launch():
    core.registerNew(LoadBalancer)
