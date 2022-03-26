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
import ipaddress


#inicializar ryu em port definida - sudo ryu-manager --ofp-tcp-listen-port 6654 router.py

class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.interfaces = {
            "10.0.1.254" : "ff:ff:ff:00:00:01", 
            "10.0.2.254" : "ff:ff:ff:00:00:02",
            "10.0.3.254" : "ff:ff:ff:00:00:03"
        }

        self.buffer = dict()
        self.arp_helper = [
            ['10.0.1.0/24', '10.0.1.254', 1],
            ['10.0.2.0/24', '10.0.2.254', 2],
            ['10.0.3.0/24', '10.0.3.254', 3]
        ]

        self.arp_table = dict()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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
            mac = self.interfaces.get(dst_ip)

            if mac:
                self.arp_reply(datapath, ether_frame, mac, arp_packet, in_port)
            else:
                self.logger.info("PACOTE NÃO ERA PARA MIM")

        elif arp_packet.opcode == 2:
            self.logger.info(f"Recebi este arp reply: {arp_packet}, e a info ethernet é {ether_frame}")
            
            self.process_arp_reply(datapath, arp_packet, in_port)

    def process_arp_reply(self, datapath, arp_packet, in_port):
        self.arp_table[arp_packet.src_ip] = (arp_packet.src_mac, in_port)
        
        self.logger.info(f"Vou enviar um flowmod para quando receber um pacote para o {arp_packet.src_ip}, vai sai pela porta {in_port}, srcmac {arp_packet.src_mac}, dstmac {arp_packet.dst_mac}")
        #Definir os parâmetros para dar match (porta de entrada, destino e source layer 2)

        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                                    ipv4_dst=arp_packet.src_ip)

        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(eth_src=arp_packet.dst_mac),
                datapath.ofproto_parser.OFPActionSetField(eth_dst=arp_packet.src_mac),
                datapath.ofproto_parser.OFPActionOutput(in_port, 0)]

        self.add_flow(datapath, 32768, match, actions)

        for packet in self.buffer[arp_packet.src_ip]:
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
        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(eth_dst=eth.src),
                datapath.ofproto_parser.OFPActionSetField(eth_src=eth.dst),
                datapath.ofproto_parser.OFPActionOutput(port, 0)]

        #actions = [datapath.ofproto_parser.datapath.ofproto_parser.OFPActionOutput(port, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=packet)
        datapath.send_msg(out)

    def find_arp(self, datapath, network, packet) -> int:
        for subnet,ip,port in self.arp_helper:
                if ipaddress.IPv4Address(network.dst) in ipaddress.IPv4Network(subnet):
                    self.logger.info(f"O IP {network.dst} está na subnet {subnet}, vou mandar ARP request com o endereço {ip} com mac {self.interfaces[ip]} e vai sair pela porta {port}")
                    
                    self.buffer.setdefault(network.dst, [])
                    self.buffer[network.dst].append(packet)

                    self.send_arp(datapath, network.dst, ip, port, self.interfaces[ip])
                    return port


    def process_icmp(self, datapath, packet:packet, network, eth, port) -> None:
        #self.logger.info(network['dst'])

        self.logger.info(f"INFO DA TABELA: {self.arp_table}")

        if network.dst in self.interfaces:
            self.logger.info(f"O PING É PARA MIM, NA INTERFACE {network.dst} mac {self.interfaces[network.dst]}")
            self.reply_icmp(datapath, packet.get_protocol(icmp.icmp), network, eth, port, packet)
        elif network.dst in self.arp_table:
            arp_info = self.arp_table[network.dst]
            self.logger.info(f"O {network.dst} ESTÁ NA TABELA")
            for subnet,ip,port in self.arp_helper:
                if ipaddress.IPv4Address(network.dst) in ipaddress.IPv4Network(subnet):
                    self.send_ip(datapath, packet, arp_info[1], self.interfaces[ip], arp_info[0])
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
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("\nESTOU A INSTALAR UM FLOW!!!!!\n")

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
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