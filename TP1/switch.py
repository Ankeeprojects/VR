from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flowe(datapath, 0, match, actions)
    
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignorar pacotes LLDP
            return

        dst = eth.dst
        src = eth.src

        #ID do switch
        dpid = datapath.id

        #Adiciona entrada no dicionário se o switch não tiver comunicado anteriormente
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.match['in_port'])

        #Associa endereço MAC a porta do switch
        self.mac_to_port[dpid][src] = msg.match['in_port']

        #Avalia se o destino já está na tabela
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            #Flood se não estiver
            out_port = ofproto.OFPP_FLOOD

        #Definir action como enviar pela porta escolhida
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        #Se o destino for conhecido, adicionar o flow ao switch
        if out_port != ofproto.OFPP_FLOOD:
             #Definir os parâmetros para dar match (porta de entrada, destino e source layer 2)
            match = datapath.ofproto_parser.OFPMatch( 
            eth_dst=dst)

            self.add_flowe(datapath, msg.match['in_port'], match, actions)

        #Reenviar o pacote de volta para o switch
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=msg.match['in_port'],
            actions=actions, data=msg.data)
        datapath.send_msg(out)
    
    def add_flowe(self, datapath, in_port, match, actions):
        ofproto = datapath.ofproto

        inst = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        #Criar e enviar o FlowMod, que adiciona um flow para os parâmetros definidos
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match,
            priority=ofproto.OFP_DEFAULT_PRIORITY, instructions=inst)
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