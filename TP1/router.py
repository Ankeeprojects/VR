from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
import ipaddress


#inicializar ryu em port definida - sudo ryu-manager --ofp-tcp-listen-port 6654 router.py

class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.interfaces = {
            "10.0.1.254" : ("ff:ff:ff:00:00:01", 1),
            "10.0.2.254" : ("ff:ff:ff:00:00:02", 2),
            "10.0.3.254" : ("ff:ff:ff:00:00:03", 3)
        }
        self.buffer = dict()
        self.arp_helper = [
            ['10.0.1.0/24', '10.0.1.254'],
            ['10.0.2.0/24', '10.0.2.254'],
            ['10.0.3.0/24', '10.0.3.254']
        ]


    def process_arp(self, datapath, packet:packet, ether_frame:ethernet, in_port:int) -> None:
        arp_packet = packet.get_protocol(arp.arp)

        if arp_packet.opcode == 1: 
            dst_ip = arp_packet.dst_ip
            mac = self.interfaces.get(dst_ip)[0]

            if mac:
                self.arp_reply(datapath, ether_frame, mac, arp_packet, in_port)
            else:
                self.logger.info("PACOTE NÃO ERA PARA MIM")

        elif arp_packet.opcode == 2:
            pass

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
        

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info(pkt.get_protocol(arp.arp))
            #self.logger.info(f"{type(datapath)}\n{type(pkt)}\n{type(eth)}\n{type(msg.in_port)}")
            self.process_arp(datapath, pkt, eth, msg.in_port)
        else:
            if network:
                self.logger.info(f"O pacote é do {network.src}")
                self.process_ip(datapath, pkt, network)
        #self.logger.info(network)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignorar pacotes LLDP
            return

    def process_ip(self, datapath, packet:packet, network) -> None:
        #self.logger.info(network['dst'])
        
        for subnet,mac in self.arp_helper:
            if ipaddress.IPv4Address(network.dst) in ipaddress.IPv4Network(subnet):
                self.logger.info(f"O IP {network.dst} está na subnet {subnet}, vou mandar ARP request com o mac {mac}")
                
                self.buffer.setdefault(network.dst, [])
                self.buffer[network.dst].append(packet)
        #self.add_flow()

    def add_flow(self, datapath, dst, src, actions):
        ofproto = datapath.ofproto

        #Definir os parâmetros para dar match (porta de entrada, destino e source layer 2)
        match = datapath.ofproto_parser.OFPMatch(
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        #Criar e enviar o FlowMod, que adiciona um flow para os parâmetros definidos acima
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
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