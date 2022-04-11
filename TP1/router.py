from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import udp

import ipaddress
import threading
import time
import json


#inicializar ryu em port definida - sudo ryu-manager --ofp-tcp-listen-port 6654 router.py

class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        
        self.mac_to_port = {}
        self.interfaces = dict()
        self.multicast_address = '224.0.0.10'

        self.interfaces[4] = {
            "10.0.1.254" : "ff:ff:ff:00:00:01", 
            "10.0.2.254" : "ff:ff:ff:00:00:02",
            "10.0.3.254" : "ff:ff:ff:00:00:03",
            "10.0.4.1" : "ff:ff:ff:00:00:04"
        }
        
        self.interfaces[5] = {
            "10.0.4.2" : "ff:ff:ff:00:00:05", 
            "10.0.5.254" : "ff:ff:ff:00:00:06",
            "10.0.6.1" : "ff:ff:ff:00:00:07",
            "10.0.9.254" : "ff:ff:ff:00:00:0b"
        }

        self.interfaces[7] = {
            "10.0.7.254" : "ff:ff:ff:00:00:08", 
            "10.0.8.254" : "ff:ff:ff:00:00:09",
            "10.0.6.2" : "ff:ff:ff:00:00:0a",
            "10.0.10.254" : "ff:ff:ff:00:00:0c"
        }

        self.buffer = dict()
        """
        self.buffer[4] = dict()
        self.buffer[5] = dict()
        self.buffer[7] = dict()
"""

        self.arp_helper = dict()

        self.arp_helper[4] = [
            ['10.0.1.0/24', '10.0.1.254', 1],
            ['10.0.2.0/24', '10.0.2.254', 2],
            ['10.0.3.0/24', '10.0.3.254', 3],
            ['10.0.4.0/24', '10.0.4.1', 4]
        ]

        self.arp_helper[5] = [
            ['10.0.4.0/24', '10.0.4.2', 1],
            ['10.0.5.0/24', '10.0.5.254', 2],
            ['10.0.6.0/24', '10.0.6.1', 3],
            ['10.0.9.0/24', '10.0.9.254', 4]
        ]

        self.arp_helper[7] = [
            ['10.0.6.0/24', '10.0.6.2', 1],
            ['10.0.7.0/24', '10.0.7.254', 2],
            ['10.0.8.0/24', '10.0.8.254', 3],
            ['10.0.10.0/24', '10.0.10.254', 4]
        ]

        self.arp_table = dict()

        """
        self.arp_table[4] = dict()
        self.arp_table[5] = dict()
        self.arp_table[7] = dict()
        """
        self.routers = dict()

        self.rotas = dict()
        """
        self.rotas[4] = dict()
        self.rotas[5] = dict()
        self.rotas[7] = dict()
        """
        
        for id in [4,5,7]:
            self.arp_table[id] = dict()
            self.routers[id] = None
            self.buffer[id] = dict()
            self.rotas[id] = dict()
            
        threading.Thread(target=self.rip_announcements, args=(4,)).start()
        threading.Thread(target=self.rip_announcements, args=(5,)).start()
        threading.Thread(target=self.rip_announcements, args=(7,)).start()
    
    def rip_announcements(self, id):
        while True:
            time.sleep(3)
            #self.logger.info(f"O meu DP é o {self.routers[id]}")

            if self.rotas[id]:
                self.send_rip_update(self.routers[id], self.rotas[id])

    def send_rip_update(self, datapath, rotas):
        for interface_ip, mac_add in self.interfaces[datapath.id].items():
            port = self.get_port(datapath.id, interface_ip)
            
            e = ethernet.ethernet(src=mac_add, dst='ff:ff:ff:ff:ff:ff', ethertype=2048)
            i = ipv4.ipv4(version=4, proto=17, src=interface_ip, dst=self.multicast_address)
            u = udp.udp(src_port=36000, dst_port=36000)
            
            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(i)
            p.add_protocol(u)
            p.add_protocol(json.dumps(rotas).encode('utf-8'))
            p.serialize()

            actions = [datapath.ofproto_parser.OFPActionOutput(port, 0)]

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=0xffffffff,
                in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=p.data)
        
            datapath.send_msg(out)

    def get_port(self, id, ip):
        for entry in self.arp_helper[id]:
            if entry[1] == ip:
                return entry[2]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.routers[datapath.id] = datapath
        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def process_arp(self, datapath, packet:packet, ether_frame:ethernet, in_port:int) -> None:
        arp_packet = packet.get_protocol(arp.arp)

        if arp_packet.opcode == 1: 
            self.logger.info("RECEBI UM PACOTE ARP!!!!!")

            dst_ip = arp_packet.dst_ip
            mac = self.interfaces[datapath.id].get(dst_ip)

            if mac:
                self.arp_reply(datapath, ether_frame, mac, arp_packet, in_port)
            else:
                self.logger.info("PACOTE NÃO ERA PARA MIM")

        elif arp_packet.opcode == 2:
            self.logger.info(f"Recebi este arp reply: {arp_packet}, e a info ethernet é {ether_frame}")
            
            self.process_arp_reply(datapath, arp_packet, in_port)

    def process_arp_reply(self, datapath, arp_packet, in_port):
        self.arp_table[datapath.id][arp_packet.src_ip] = (arp_packet.src_mac, in_port)
        
        self.logger.info(f"Vou enviar um flowmod para quando receber um pacote para o {arp_packet.src_ip}, vai sai pela porta {in_port}, srcmac {arp_packet.src_mac}, dstmac {arp_packet.dst_mac}")
        #Definir os parâmetros para dar match (porta de entrada, destino e source layer 2)

        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                                    ipv4_dst=arp_packet.src_ip)

        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(eth_src=arp_packet.dst_mac),
                datapath.ofproto_parser.OFPActionSetField(eth_dst=arp_packet.src_mac),
                datapath.ofproto_parser.OFPActionOutput(in_port, 0)]

        #(custo, prox hop, interface)
        self.rotas[datapath.id][arp_packet.src_ip] = (1, arp_packet.src_ip, in_port)
        
        self.logger.info(f"TABELA DE ENCAMINHAMENTO DO {datapath.id}: {self.rotas[datapath.id]}")

        self.add_flow(datapath, 32768, match, actions)

        for packet in self.buffer[datapath.id][arp_packet.src_ip]:
            self.send_ip(datapath, packet, in_port, arp_packet.dst_mac, arp_packet.src_mac)

    def send_ip(self, datapath, packet, in_port, src_mac, dst_mac):
        
        #OPENFLOW 1.3 datapath.ofproto_parser.OFPActionDecNwTtl(),

        self.logger.info(f"\n\n\nEstou a enviar um pacote {packet} pela {in_port}, para o {dst_mac}, a partir da {src_mac}\n\n\n")
        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
                datapath.ofproto_parser.OFPActionSetField(eth_src=src_mac),
                datapath.ofproto_parser.OFPActionOutput(in_port, 0)]

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=packet)
        datapath.send_msg(out)
    
    
    def arp_reply(self, datapath, ether_frame:ethernet, src_mac, arp_packet, in_port):    
        dst_ip = arp_packet.src_ip
        src_ip = arp_packet.dst_ip
        
        self.logger.info(f"ARP REQUEST {ether_frame.src} a vir de {in_port}. O IP do gajo é {dst_ip} e o que lhe vou dar é o {src_ip}")
        self.logger.info(f"Vou enviar resposta com o mac {src_mac}, vai sair pela {in_port}")
        

        e = ethernet.ethernet(ether_frame.src, src_mac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, src_mac, src_ip, ether_frame.src, dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(in_port, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

        #Switch que enviou a mensagem
        datapath = msg.datapath

        #Constantes da versão do openflow que o switch fala
        ofproto = datapath.ofproto

        #Retira o pacote que foi enviado
        pkt = packet.Packet(msg.data)

        
        #Informação de ethernet
        eth = pkt.get_protocol(ethernet.ethernet)
        network = pkt.get_protocol(ipv4.ipv4)
        #self.logger.info(f"\n\n\n RECEBI O PACOTE {msg}\n\n")

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignorar pacotes LLDP
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info(pkt.get_protocol(arp.arp))
            #self.logger.info(f"{type(datapath)}\n{type(pkt)}\n{type(eth)}\n{type(msg.in_port)}")
            self.process_arp(datapath, pkt, eth, msg.match['in_port'])
        elif network and network.proto == 1:
                self.logger.info(f"O pacote é ICMP MAN")
                self.logger.info(f"O pacote é {network}")

                self.process_icmp(datapath, pkt, network, eth, msg.match['in_port'])
        elif network and network.dst==self.multicast_address:
            rotas = json.loads(pkt[-1])
            
            self.logger.info(f"SOU O {datapath.id} E RECEBI ROTAS DO {network.src}: {rotas}")
            
            self.add_rotas(rotas, datapath.id, network.src, eth.src, msg.match['in_port'])
        #self.logger.info(network)

    def reply_icmp(self, datapath, icmp_pkt, network, eth, port, packet):
        """
        if network.src not in self.arp_table:
            self.find_arp(datapath, network, packet)

        e = ethernet.ethernet(src=eth.dst, dst=eth.src, ethertype=eth.ethertype)
        
        i = ipv4.ipv4(src=network.dst, dst=network.src, proto=network.proto)

        icmp_header = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=icmp_pkt.data)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(i)
        p.add_protocol(icmp_header)
        p.serialize()
        
        self.logger.info(f"\n\nO pacote ICMP REPLY vai para o {type(network.src)} e o cabeçalho é o {icmp_header}\n\n")
        """
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                                    ipv4_dst=network.dst, 
                                                    ipv4_src=network.src,
                                                    ip_proto=1, icmpv4_type=8)
        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(ipv4_dst=network.src),
                datapath.ofproto_parser.OFPActionSetField(ipv4_src=network.dst),
                datapath.ofproto_parser.OFPActionSetField(eth_dst=eth.src),
                datapath.ofproto_parser.OFPActionSetField(eth_src=eth.dst),
                datapath.ofproto_parser.OFPActionSetField(icmpv4_type=0),
                datapath.ofproto_parser.OFPActionSetField(icmpv4_code=0),
                datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_IN_PORT)]

        actions2 = [datapath.ofproto_parser.OFPActionSetField(ipv4_dst=network.src),
                datapath.ofproto_parser.OFPActionSetField(ipv4_src=network.dst),
                datapath.ofproto_parser.OFPActionOutput(1)]
        self.add_flow(datapath, 32768, match, actions)
        
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=packet)
        datapath.send_msg(out)

    def find_arp(self, datapath, network, packet) -> int:
        for subnet,ip,port in self.arp_helper[datapath.id]:
                if ipaddress.IPv4Address(network.dst) in ipaddress.IPv4Network(subnet):
                    self.logger.info(f"O IP {network.dst} está na subnet {subnet}, vou mandar ARP request com o endereço {ip} com mac {self.interfaces[datapath.id][ip]} e vai sair pela porta {port}")
                    
                    self.buffer[datapath.id].setdefault(network.dst, [])
                    self.buffer[datapath.id][network.dst].append(packet)

                    self.send_arp(datapath, network.dst, ip, port, self.interfaces[datapath.id][ip])
                    return port


    def process_icmp(self, datapath, packet:packet, network, eth, port) -> None:
        #self.logger.info(network['dst'])

        self.logger.info(f"INFO DA TABELA: {self.arp_table[datapath.id]}")

        if network.dst in self.interfaces[datapath.id]:
            self.logger.info(f"O PING É PARA MIM, NA INTERFACE {network.dst} mac {self.interfaces[datapath.id][network.dst]}")
            self.reply_icmp(datapath, packet.get_protocol(icmp.icmp), network, eth, port, packet)
        elif network.dst in self.arp_table[datapath.id]:
            arp_info = self.arp_table[datapath.id][network.dst]
            self.logger.info(f"O {network.dst} ESTÁ NA TABELA")
            for subnet,ip,port in self.arp_helper[datapath.id]:
                if ipaddress.IPv4Address(network.dst) in ipaddress.IPv4Network(subnet):
                    self.send_ip(datapath, packet, arp_info[1], self.interfaces[datapath.id][ip], arp_info[0])
                    break
        else:
            self.find_arp(datapath, network, packet)
            
    
    def send_arp(self, datapath, dst_ip, src_ip, port, src_mac):
        e = ethernet.ethernet(src=src_mac, dst='ff:ff:ff:ff:ff:ff', ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=1, src_mac=src_mac, src_ip=src_ip, dst_mac='00:00:00:00:00:00', dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        self.logger.info(f"O pacote ARP vai para do {src_mac} para  ")
        actions = [datapath.ofproto_parser.OFPActionOutput(port, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
 
 #self.add_flow(datapath, arp_packet.src_ip, arp_packet.dst_mac, arp_packet.src_mac, in_port)
    def remove_flow(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0,table_id, ofproto.OFPFC_DELETE, 0, 0, 1,ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod
    
    
    def add_rotas(self, rotas : dict, id : int, source : str, dst_mac,  port : int):
        for ip, dados in rotas.items():
            comp = self.rotas[id]
            if (ip in comp and dados[0]+1 < comp[ip][0]):
                self.rotas[id][ip] = [dados[0]+1, source, port]    
            elif ip not in comp:
                datapath = self.routers[id]
                match =  datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=ip,
                                                    ip_proto=1)
                self.remove_flow(self.routers[id], 0, match, [])
                self.rotas[id][ip] = [dados[0]+1, source, port]

                src_mac = self.find_mac(id, ip)

                self.logger.info(f"O ENDEREÇO MAC É O {src_mac} para mandar para o {dst_mac} de ip {ip}")
                actions = [ 
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
                    datapath.ofproto_parser.OFPActionSetField(eth_src=src_mac),
                    datapath.ofproto_parser.OFPActionOutput(port, 0)]

                self.add_flow(self.routers[id], 32769, match, actions)

    def find_mac(self, id, ip_dst):
        for vals in self.arp_helper[id]:
            if ipaddress.IPv4Address(ip_dst) in ipaddress.IPv4Network(vals[0]):
                return self.interfaces[id][vals[1]]
        
        return 'ff:ff:ff:00:00:01'

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"\nSOU O {datapath.id} E ESTOU A INSTALAR UM FLOW!!!!! {actions} {match}\n")

        # construct flow_mod message and send it.
        if actions:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        else:
            inst = actions

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

        #codigo useful no futuro
"""
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
"""