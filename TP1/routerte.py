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
import datetime


#inicializar ryu em port definida - ryu-manager --ofp-tcp-listen-port 6654 router.py

#verificar flows sudo ovs-ofctl -O OpenFlow13 dumpflows s4

class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        
        self.interfaces = dict()
        
        #Definição do endereço de multicast para difusão do protocolo de encaminhamento
        self.multicast_address = '224.0.0.10'
        self.lock = threading.Lock()

        #Associação das interfaces de cada router da topologia, de acordo com o seu ID
        self.interfaces[4] = {
            "10.0.1.254" : "ff:ff:ff:00:00:01", 
            "10.0.2.254" : "ff:ff:ff:00:00:02",
            "10.0.3.254" : "ff:ff:ff:00:00:03",
            "10.0.4.1" : "ff:ff:ff:00:00:04",
            "10.0.11.1" : "ff:ff:ff:00:00:0d"
        }
        
        self.interfaces[5] = {
            "10.0.4.2" : "ff:ff:ff:00:00:05", 
            "10.0.5.254" : "ff:ff:ff:00:00:06",
            "10.0.6.1" : "ff:ff:ff:00:00:07",
            "10.0.9.254" : "ff:ff:ff:00:00:0b",
            "10.0.12.5" : "ff:ff:ff:00:00:0f"
        }

        self.interfaces[7] = {
            "10.0.7.254" : "ff:ff:ff:00:00:08", 
            "10.0.8.254" : "ff:ff:ff:00:00:09",
            "10.0.6.2" : "ff:ff:ff:00:00:0a",
            "10.0.10.254" : "ff:ff:ff:00:00:0c",
            "10.0.11.2" : "ff:ff:ff:00:00:0e",
            "10.0.13.7" : "ff:ff:ff:00:00:10"
        }

        self.interfaces[9] = {
            "10.0.12.9" : "ff:ff:ff:00:00:11",
            "10.0.13.9" : "ff:ff:ff:00:00:12",
            "10.0.14.254" : "ff:ff:ff:00:00:13",
            "10.0.15.254" : "ff:ff:ff:00:00:14"
        }

        #Buffer para pacotes que esperam resolução do protocolo ARP
        self.buffer = dict()

        #Estrutura de apoio ao protocolo ARP, com a subrede a que cada interface pertence, assim como o seu endereço nesta
        self.arp_helper = dict()

        self.arp_helper[4] = [
            ['10.0.1.0/24', '10.0.1.254', 1],
            ['10.0.2.0/24', '10.0.2.254', 2],
            ['10.0.3.0/24', '10.0.3.254', 3],
            ['10.0.4.0/24', '10.0.4.1', 4],
            ['10.0.11.0/24', '10.0.11.1', 5]
        ]

        self.arp_helper[5] = [
            ['10.0.4.0/24', '10.0.4.2', 1],
            ['10.0.5.0/24', '10.0.5.254', 2],
            ['10.0.6.0/24', '10.0.6.1', 3],
            ['10.0.9.0/24', '10.0.9.254', 4],
            ['10.0.12.0/24', '10.0.12.5', 5]
        ]

        self.arp_helper[7] = [
            ['10.0.6.0/24', '10.0.6.2', 1],
            ['10.0.7.0/24', '10.0.7.254', 2],
            ['10.0.8.0/24', '10.0.8.254', 3],
            ['10.0.10.0/24', '10.0.10.254', 4],
            ['10.0.11.0/24', '10.0.11.2', 5],
            ['10.0.13.0/24', '10.0.13.7', 6]
        ]

        self.arp_helper[9] = [
            ['10.0.12.0/24', '10.0.12.9', 1],
            ['10.0.13.0/24', '10.0.13.9', 2],
            ['10.0.14.0/24', '10.0.14.254', 3],
            ['10.0.15.0/24', '10.0.15.254', 4]
        ]

        #Tabela ARP, que associa endereços IP a endereços MAC
        self.arp_table = dict()

        #Informação de datapath para cada um dos routers
        self.routers = dict()

        #Rotas aprendidas para cada um dos routers
        self.rotas = dict()
        
        #Vizinhos ativos de cada router
        self.vizinhos = dict()

        #Informação se a tabela foi alterada desde o último update
        self.changes = dict()
        
        #Identificadores para os grupos de cada dispositivo
        self.groupID = dict()

        for id in [4,5,7,9]:
            self.arp_table[id] = dict()
            self.routers[id] = None
            self.buffer[id] = dict()
            self.rotas[id] = dict()
            self.changes[id] = 0
            self.groupID[id] = 1
        
        #Thread para controlar os anúncios do protocolo de encaminhamento
        threading.Thread(target=self.rip_announcements, args=(4,)).start()
        threading.Thread(target=self.rip_announcements, args=(5,)).start()
        threading.Thread(target=self.rip_announcements, args=(7,)).start()
        threading.Thread(target=self.rip_announcements, args=(9,)).start()


        #Thread para manter uma noção atualizada dos vizinhos que estão ativos
        threading.Thread(target=self.timeouts, args=(4,)).start()
        threading.Thread(target=self.timeouts, args=(5,)).start()
        threading.Thread(target=self.timeouts, args=(7,)).start()
        threading.Thread(target=self.timeouts, args=(9,)).start()

    def timeouts(self, id):

        #Verificar vizinhos a cada 0.5 segundos
        while True:
            time.sleep(0.5)

            to_delete = set()
            self.lock.acquire()

            for vizinho, tempo in self.vizinhos.items():
                diferenca = datetime.datetime.now() - tempo
                
                #Averiguar se algum já não comunica há mais de 1 segundo
                if diferenca.total_seconds() > 1:
                    self.logger.info(f"O VIZINHO {vizinho} MORREU")

                    #Apagar rotas provenientes deste vizinho e enviar um flowmod para remover
                    to_delete_routes = []
                    for rota, info in self.rotas[id].items():
                        if info[1] == vizinho:
                            match =  self.routers[id].ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=rota,
                                                    ip_proto=1)

                            self.remove_flow(self.routers[id], 0, match, [])
                            to_delete_routes.append(rota)

                    if to_delete_routes:    
                        for item in to_delete_routes:
                            self.rotas[id].pop(item)
                        to_delete.add(vizinho)

            if to_delete:
                self.logger.info(f"VOU APAGAR {to_delete}")
            for vizinho in to_delete:
                self.vizinhos.pop(vizinho)


            self.lock.release()

    #Envio de anúncios RIP a cada 0.5 segundos
    def rip_announcements(self, id):
        while True:
            time.sleep(0.5)
            
            if self.changes[id] == 1:
                self.send_rip_update(self.routers[id], self.rotas[id])
            else:
                self.send_rip_update(self.routers[id], None)
    
    #Envia anúncio RIP por todas as suas interfaces
    def send_rip_update(self, datapath, rotas):
        if datapath is not None:
            for interface_ip, mac_add in self.interfaces[datapath.id].items():
                port = self.get_port(datapath.id, interface_ip)
                
                e = ethernet.ethernet(src=mac_add, dst='ff:ff:ff:ff:ff:ff', ethertype=2048)
                
                #Direciona o anúncio para o endereço de multicast
                i = ipv4.ipv4(version=4, proto=17, src=interface_ip, dst=self.multicast_address)
                u = udp.udp(src_port=36000, dst_port=36000)
                
                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(i)
                p.add_protocol(u)

                if rotas is not None:
                    #Inclui as rotas como payload
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

    #Devolve a porta correspondente ao endereço IP do dispositivo ID
    def get_port(self, id, ip):
        for entry in self.arp_helper[id]:
            if entry[1] == ip:
                return entry[2]

    #Adiciona um flow para que o dispositivo envie mensagem ao controller quando não dá match noutro flow
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #dispositivo que envia mensagem
        datapath = ev.msg.datapath

        #protocolo OpenFlow
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #Guarda as definições do dispositivo
        self.routers[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    #Define o que acontece quando o controller recebe um pacote
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

        #Ignorar pacotes LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        #Informação IPv4
        network = pkt.get_protocol(ipv4.ipv4)
        
        #Se for um pacote ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            
            self.process_arp(datapath, pkt, eth, msg.match['in_port'])
        
        #Se for um pacote ICMP (campo protocol 1 no cabeçalho IPv4)
        elif network and network.proto == 1:
            
            self.process_icmp(datapath, pkt, network, eth, msg.match['in_port'])
        
        #Se for um pacote destinado ao endereço de multicast definido
        elif network and network.dst==self.multicast_address:

            #atualiza último contacto de vizinho
            self.lock.acquire()
            self.vizinhos[network.src] = datetime.datetime.now()
            self.lock.release()     
            
            if pkt.get_protocol(udp.udp).total_length > 8:
                #Extrai rotas do pacote
                rotas = json.loads(pkt[-1])
            else:
                rotas = None

            #Averigua se as rotas serão adicionadas
            self.add_rotas(rotas, datapath.id, network.src, eth.src, msg.match['in_port'])

    #Processa um pacote ARP recebido
    def process_arp(self, datapath, packet:packet, ether_frame:ethernet, in_port:int) -> None:
        arp_packet = packet.get_protocol(arp.arp)

        #Se o pacote for um ARP REQUEST
        if arp_packet.opcode == 1: 
            dst_ip = arp_packet.dst_ip
            mac = self.interfaces[datapath.id].get(dst_ip)

            #Enviar um reply se o endereço MAC pertencer a este dispositivo, não fazer nada de outro modo (pacote é descartado)
            if mac:
                self.arp_reply(datapath, ether_frame, mac, arp_packet, in_port)
        
        #Se for um ARP REPLY            
        elif arp_packet.opcode == 2:
            self.logger.info(f"Recebi este arp reply: {arp_packet}, e a info ethernet é {ether_frame}")
            
            self.process_arp_reply(datapath, arp_packet, in_port)

    #Envia resposta a um ARP REQUEST
    def arp_reply(self, datapath, ether_frame:ethernet, src_mac, arp_packet, in_port):    
        dst_ip = arp_packet.src_ip
        src_ip = arp_packet.dst_ip
        
        self.logger.info(f"ARP REQUEST {ether_frame.src} a vir de {in_port}. O IP de origem é {dst_ip} e o que lhe vou dar é o {src_ip}")
        
        e = ethernet.ethernet(ether_frame.src, src_mac, ether.ETH_TYPE_ARP)
        
        #cabeçalho ARP: hardware address, protocolo, length dos endereços fisicos, length endereços de protocolo, opcode 
        a = arp.arp(1, 0x0800, 6, 4, 2, src_mac, src_ip, ether_frame.src, dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        #Enviar um reply pela mesma porta por onde recebemos o request
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port, 0)]

        #Não há envio de um flowmod porque arp requests não acontecem com frequência suficiente que mereça diluir a flow table
        out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=0xffffffff,
                in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=p.data)
        datapath.send_msg(out)

    def process_arp_reply(self, datapath, arp_packet, in_port):
        #É adicionada uma entrada à tabela ARP
        self.arp_table[datapath.id][arp_packet.src_ip] = (arp_packet.src_mac, in_port)
        
        #Define os parâmetros para dar match - qualquer pacote IPv4 com destino ao emissor do pacote recebido
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                                    ipv4_dst=arp_packet.src_ip)

        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(eth_src=arp_packet.dst_mac),
                datapath.ofproto_parser.OFPActionSetField(eth_dst=arp_packet.src_mac),
                datapath.ofproto_parser.OFPActionOutput(in_port, 0)]

        #A rota para este destino é adicionada à tabela: (custo, prox hop, interface)
        self.rotas[datapath.id][arp_packet.src_ip] = (1, arp_packet.src_ip, in_port)
        
        self.logger.info(f"TABELA DE ENCAMINHAMENTO DO {datapath.id}: {self.rotas[datapath.id]}")

        self.add_flow(datapath, 32768, match, actions)

        self.changes[datapath.id] = 1
        #Envia todos os pacotes em buffer para o destino
        for packet in self.buffer[datapath.id][arp_packet.src_ip]:
            self.send_ip(datapath, packet, in_port, arp_packet.dst_mac, arp_packet.src_mac)


    #Envia pacote pela porta in_port do datapath, alterando info ethernet para src_mac e dst_mac
    def send_ip(self, datapath, packet, in_port, src_mac, dst_mac):

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
    

    #Processar pacote ICMP recebido
    def process_icmp(self, datapath, packet:packet, network, eth, port) -> None:

        self.logger.info(f"INFO DA TABELA: {self.arp_table[datapath.id]}")

        #Avalia se o destino do ping é a interface do router
        if network.dst in self.interfaces[datapath.id]:
            self.logger.info(f"O PING É PARA O ROUTER {datapath.id}, NA INTERFACE {network.dst} MAC {self.interfaces[datapath.id][network.dst]}")
            self.reply_icmp(datapath, packet.get_protocol(icmp.icmp), network, eth, port, packet)
        
        #Caso não seja, vê se o destino está na arp_table
        elif network.dst in self.arp_table[datapath.id]:
            arp_info = self.arp_table[datapath.id][network.dst]

            for subnet,ip,port in self.arp_helper[datapath.id]:
                #averiguar se o endereço está nesta subrede
                if ipaddress.IPv4Address(network.dst) in ipaddress.IPv4Network(subnet):
                    self.send_ip(datapath, packet, arp_info[1], self.interfaces[datapath.id][ip], arp_info[0])
                    break
        #Caso em que o endereço não é do router, e não está na tabela ARP
        else:
            self.find_arp(datapath, network, packet)

    #Preparar resposta ICMP e adicionar flow para comunicações entre estes intervenientes       
    def reply_icmp(self, datapath, icmp_pkt, network, eth, port, packet):
        
        #Match para ethernet, entre os dois endereços IPv4, e protocolo ICMP (ip_proto=1), Request (ICMP type 8)
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                                    ipv4_dst=network.dst, 
                                                    ipv4_src=network.src,
                                                    ip_proto=1, icmpv4_type=8)
        
        #Endereços IPv4 e MAC são invertidos para responder, e o tipo e código de ICMP alterados para 0 (Reply)
        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(ipv4_dst=network.src),
                datapath.ofproto_parser.OFPActionSetField(ipv4_src=network.dst),
                datapath.ofproto_parser.OFPActionSetField(eth_dst=eth.src),
                datapath.ofproto_parser.OFPActionSetField(eth_src=eth.dst),
                datapath.ofproto_parser.OFPActionSetField(icmpv4_type=0),
                datapath.ofproto_parser.OFPActionSetField(icmpv4_code=0),
                datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_IN_PORT)]

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

    
    #Enviar um pacote ARP REQUEST para pedir o dst_ip
    def send_arp(self, datapath, dst_ip, src_ip, port, src_mac):
        e = ethernet.ethernet(src=src_mac, dst='ff:ff:ff:ff:ff:ff', ethertype=ether.ETH_TYPE_ARP)

        #Indicar que o protocolo é IPv4 (0x0800), o hardware length (MAC address) são 6 bytes, protocol length são 4 bytes (IPv4)
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=1, src_mac=src_mac, src_ip=src_ip, dst_mac='00:00:00:00:00:00', dst_ip=dst_ip)
        
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        self.logger.info(f"A enviar pacote ARP para {dst_ip}")
        
        actions = [datapath.ofproto_parser.OFPActionOutput(port, 0)]
        
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        
        datapath.send_msg(out)
 
    #Remover flow do dispositivo
    def remove_flow(self, datapath, table_id, match, instructions):
        
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0,table_id, ofproto.OFPFC_DELETE, 0, 0, 1,ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY, 0,
                                                      match, instructions)
        
        datapath.send_msg(flow_mod)
    
    #Averigua se o dicionário de rotas contém alguma melhor do que as que já existem/alguma rota nova
    def add_rotas(self, rotas : dict, id : int, source : str, dst_mac,  port : int):
        if rotas is not None:
            for ip, dados in rotas.items():
                comp = self.rotas[id]

                #Se já houver uma rota e o custo for superior 
                if ip in comp and dados[0]+1 == comp[ip][0]:
                    pass
                
                elif (ip in comp and dados[0]+1 < comp[ip][0]):
                    self.rotas[id][ip] = [dados[0]+1, source, port]   
                    
                    self.logger.info(f"SOU O {datapath.id} E RECEBI UMA ROTA MELHOR DO {source}: {ip} com custo {dados[0]+1}") 
                    
                    src_mac = self.find_mac(id, ip)

                    match =  datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_dst=ip)

                    actions = [ 
                        datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
                        datapath.ofproto_parser.OFPActionSetField(eth_src=src_mac),
                        datapath.ofproto_parser.OFPActionOutput(port, 0)]

                    #removemos o flow anterior para que o melhor caminho seja o escolhido
                    self.remove_flow(self.routers[id], 0, match, [])
                    
                    self.add_flow(self.routers[id], 32769, match, actions) 

                    self.changes[id] = 1               
                elif ip not in comp:
                    datapath = self.routers[id]
                    
                    match =  datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_dst=ip)

                    self.rotas[id][ip] = [dados[0]+1, source, port, self.groupID[id]]

                    src_mac = self.find_mac(id, ip)

                    bucket_actions = [ 
                        datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
                        datapath.ofproto_parser.OFPActionSetField(eth_src=src_mac),
                        datapath.ofproto_parser.OFPActionOutput(port, 0)
                        ]

                    actions = [datapath.ofproto_parser.OFPActionGroup(self.groupID[id])]

                    bucket = [datapath.ofproto_parser.OFPBucket(
                                weight=1,
                                watch_port=port,
                                watch_group=0,
                                actions=bucket_actions
                                )]
                    
                    group = datapath.ofproto_parser.OFPGroupMod(datapath, 0, 1, self.groupID[id], bucket)

                    datapath.send_msg(group)

                    self.groupID[id]+=1

                    self.add_flow(self.routers[id], 32769, match, actions)

                    self.changes[id] = 1

    #Encontra o endereço MAC da interface do dispositivo nessa subrede, devolve um endereço genérico se esta não existir
    def find_mac(self, id, ip_dst):
        for vals in self.arp_helper[id]:
            if ipaddress.IPv4Address(ip_dst) in ipaddress.IPv4Network(vals[0]):
                return self.interfaces[id][vals[1]]
        
        return 'ff:ff:ff:00:00:aa'

    #Adiciona um flow ao dispositivo
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"\nSOU O ROUTER {datapath.id} E ESTOU A INSTALAR UM FLOW!!!!! {actions} {match}\n")

        if actions:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        else:
            inst = actions

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
