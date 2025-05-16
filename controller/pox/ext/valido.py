import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp


log = core.getLogger()

CLIENT_GW_IP = IPAddr("10.0.0.1")
CLIENT_GW_MAC = EthAddr("00:00:00:00:00:01")
SERVER_GW_IP = IPAddr("192.168.0.1")
SERVER_GW_MAC = EthAddr("01:00:00:00:00:01")


class LoadBalancer():

    servers_discovered = 0
    servers = {}  # id: {mac, ip, port}
    conn_track = {}  # key: 5-tuple, value: client MAC

    load = {}

    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        self.get_server_info(event, max_servers=10)

    def config_timer(self, recurrence=3):
        Timer(recurrence, self.send_stat_req, recurring=True)

    def _handle_PacketIn(self, event):
        pkt = event.parsed
        ip_pkt = pkt.find('ipv4')
        eth_pkt = pkt.find('ethernet')

        if ip_pkt:
            log.info("Got IP packet\t{} -> {}".format(ip_pkt.srcip, ip_pkt.dstip))

            if ip_pkt.dstip == CLIENT_GW_IP:  # DNAT
                l4 = ip_pkt.payload
                if isinstance(l4, (tcp, udp)):
                    conn_key = (str(ip_pkt.srcip), l4.srcport, str(ip_pkt.dstip), l4.dstport, ip_pkt.protocol)
                    self.conn_track[conn_key] = eth_pkt.src
                    log.info("Connessione tracciata: %s => %s", conn_key, eth_pkt.src)

                srv_no = self.get_best_server()

                if srv_no is not None:
                    ip_pkt.dstip = IPAddr(self.servers[srv_no]['ip'])

                    l4 = ip_pkt.payload
                    if isinstance(l4, (tcp, udp)):
                        l4.csum = 0  # Disattiva il calcolo del checksum per evitare crash



                    eth = ethernet()
                    eth.type = ethernet.IP_TYPE
                    eth.src = SERVER_GW_MAC
                    eth.dst = EthAddr(self.servers[srv_no]['mac'])
                    eth.payload = ip_pkt

                    msg = of.ofp_packet_out()
                    msg.data = eth.pack()
                    msg.actions.append(of.ofp_action_output(port=self.servers[srv_no]['port']))
                    event.connection.send(msg)

                    log.info("Packet redirected: client IP {} -> server IP {} (MAC {}, port {}), original dst IP {}"
                             .format(ip_pkt.srcip,
                                     self.servers[srv_no]['ip'],
                                     self.servers[srv_no]['mac'],
                                     self.servers[srv_no]['port'],
                                     SERVER_GW_IP))
                    return

            elif ip_pkt.srcip in [srv['ip'] for srv in self.servers.values()]:  # SNAT
                log.info("Sto realizzando il reverse Path")
                ip_pkt.srcip = CLIENT_GW_IP
                l4 = ip_pkt.payload
                conn_key = None
                client_mac = None

                if isinstance(l4, (tcp, udp)):
                    conn_key = (str(ip_pkt.dstip), l4.dstport, str(ip_pkt.srcip), l4.srcport, ip_pkt.protocol)
                    client_mac = self.conn_track.get(conn_key)

                if client_mac is None:
                    log.warn(" Connessione non trovata nella conn_track: %s. Pacchetto scartato.", conn_key)
                    return

                

                eth = ethernet()
                eth.type = ethernet.IP_TYPE
                eth.src = CLIENT_GW_MAC
                eth.dst = EthAddr(client_mac)
                eth.payload = ip_pkt  

                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=1))  # Assumed client port
                event.connection.send(msg)

                log.info("SNAT: risposta del server inoltrata a %s (MAC %s)", ip_pkt.dstip, client_mac)
                return

        arp_pkt = pkt.find('arp')
        if arp_pkt and arp_pkt.opcode == arp.REPLY:
            no = self.servers_discovered + 1
            self.servers_discovered = no
            self.servers[no] = {
                'ip': str(arp_pkt.protosrc),
                'mac': str(arp_pkt.hwsrc),
                'port': event.port,
                'capacity': 1000
            }
            log.info("Server scoperto: %s", self.servers[no])
            return

        log.warn("Packet is neither IPv4 nor ARP reply, ignoring...")

    def get_server_info(self, event, max_servers):
        for s in range(1, max_servers + 1):
            arp_req = arp()
            arp_req.hwsrc = SERVER_GW_MAC
            arp_req.opcode = arp.REQUEST
            arp_req.protosrc = SERVER_GW_IP
            arp_req.protodst = IPAddr(f"192.168.{s}.1")

            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = EthAddr.BROADCAST
            ether.src = SERVER_GW_MAC
            ether.payload = arp_req

            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=2))
            event.connection.send(msg)

    def send_stat_req(self):
        for con in core.openflow._connections.values():
            con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_FlowStatsReceived(self, event):
        pass  # Stub: da implementare se vuoi analizzare i flussi

    def get_best_server(self):
        if not self.servers:
            log.warn("Nessun server disponibile per il bilanciamento")
            return None
        return list(self.servers.keys())[0]  # semplice scelta del primo


def launch():
    core.registerNew(LoadBalancer)
