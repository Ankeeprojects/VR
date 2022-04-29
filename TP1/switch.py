from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

#classe de app do Ryu
class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)
        
        
        self.mac_table = {}
    
    #Evento do switch pedir info das suas propriedades
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #switch que enviou a mensagem
        datapath = ev.msg.datapath

        #protocolo de OpenFlow
        ofproto = datapath.ofproto

        #parser do OpenFlow
        parser = datapath.ofproto_parser

        #Instalar o flow de enviar para o controlador caso não haja match de um pacote
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #Instruções do que fazer quando um pacote dá match neste flow
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        #Construção do flowmod
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    #Evento quando o controlador recebe um pacote
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #Identificador do switch, para podermos ter vários switches com o mesmo controller
        dpid = datapath.id
        self.mac_table.setdefault(dpid, {})

        #Decomposição do pacote para sabermos a origem e destino do pacote a nível de ethernet
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        #porta de entrada do pacote
        in_port = msg.match['in_port']

        #self.logger.info("Sou o  %s e recebi um pacote do %s para o %s pela porta %s", dpid, src, dst, in_port)

        #Anotamos a porta por onde o endereço é acessível na mac table deste switch
        self.mac_table[dpid][src] = in_port

        #Se o destino já for conhecido, enviar pela porta, de outro modo fazer flood
        if dst in self.mac_table[dpid]:
            out_port = self.mac_table[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        #Definir que a ação a ter é enviar pela porta de saída
        actions = [parser.OFPActionOutput(out_port)]

        #Caso a porta seja conhecida, adicionar um flowmod para não ter que comunicar novamente com o controlador
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst)
            self.logger.info(f"ESTOU A INSTALAR UM FLOW PARA O MAC {dst}, sai pela porta {in_port}")
            self.add_flow(datapath, 32769, match, actions)

        #Enviar o pacote de volta para o switch
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)