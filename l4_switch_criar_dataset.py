# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

# Criar Thread para criar o dataset
from ryu.lib import hub

# Adicionar data e hora aos pacotes capturados
from datetime import datetime

# variavel lista utilizada para salvar os dados dos pacotes que são salvos nos arquivos
lista_global = []

# variavel lista de controle para armazenar apenas o primeiro pacote de uma sessão
lista_pkt_recebidos = []


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        hub.spawn(self.myfunction)

    # Thread para salvar em um arquivo o conteudo da variavel V que contem o trafego de rede capturado no intervalo t 
    def myfunction(self):
        self.logger.info("")
        #seg = 1
        print(f'Carregando NOS...')
        hub.sleep(15)
        print('A coleta do tráfego de rede foi iniciada.\nO tráfego de rede já pode ser gerado...')
        seg = 0
        while True:
            
            self.logger.info("Tempo de coleta - %d segundo (s)", seg)
            seg = seg + 30

            if lista_global:
                string = ''
                for i in range (len(lista_global)):
                    for j in range (len(lista_global[i])):
                        # Utilizado para não inserir a virgula no inicio
                        if j == 0:
                            string = string + str(lista_global[i][j])
                        else:
                            string =  string + ','+   str(lista_global[i][j])   
                        ####string = str(lista_global[i][j]) + ',' + string

                # Limpar a lista global
                lista_global.clear()

                # Salvar o tráfego coletado em um arquivo
                arquivo = open('coleta_ddos_icmp.csv','a')
                arquivo.writelines(string)
                arquivo.close()
            hub.sleep(30)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # Novo pacote Packet_IN chegou ao controlador
        # Limpar os dados do ultimo trafego para armazenar o novo pacote
        cada_pacote = []
                
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)



        # TESTE
        priority = 1 

        global lista_global

        # Capturar data e hora do pacote recebido
        now = datetime.now()
        data_hora = datetime.now()
        

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                origem = 'sw'+str(dpid) + '-p' + str(in_port)
                
#                print(f'PROTOCOLO: {protocol}')

                ######################

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    pi = pkt.get_protocol(icmp.icmp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,          eth_dst=dst, eth_src=src,        ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                    
                    # Armazenar os dados extraidos do cabecalho ICMP
                    cada_pacote = [dpid, in_port, data_hora, src, dst, srcip, dstip, protocol, -1, -1, -1, -1, -1,-1,-1,-1, -1, ip.total_length, ip.ttl, pi.type, pi.code ] 
                    # quebra de linha
                    cada_pacote.append('\n')
                    
                    # Verificar pacote único - não repetido
                    pkt_recebido = src + '-' + dst + '-' + srcip + '-' + dstip +'-' + str(protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,    eth_dst=dst, eth_src=src,                       ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,)

                    # Armazenar os dados extraidos do cabecalho TCP

 #                   print(f'WS --->>>{t.window_size}')

                    cada_pacote = [dpid, in_port, data_hora, src, dst, srcip, dstip, protocol, t.src_port, t.dst_port, -1, -1, t.has_flags(tcp.TCP_SYN), t.has_flags(tcp.TCP_FIN), t.has_flags(tcp.TCP_RST), t.has_flags(tcp.TCP_ACK), t.has_flags(tcp.TCP_URG), ip.total_length, ip.ttl, -1, -1 ]

                    # t.has_flags(tcp.TCP_SYN), t.has_flags(tcp.TCP_FIN), t.has_flags(tcp.TCP_RST), t.has_flags(tcp.TCP_ACK)  ]
                    
                    # quebra de linha
                    cada_pacote.append('\n')

                    pkt_recebido = src + '-' + dst + '-' + srcip + '-' + dstip +'-' + str(protocol) +'-'+ str(t.src_port)+'-'+ str(t.dst_port)+'-'+ str(t.has_flags(tcp.TCP_SYN))+'-'+ str(t.has_flags(tcp.TCP_FIN))+'-'+ str(t.has_flags(tcp.TCP_RST))+'-'+ str(t.has_flags(tcp.TCP_ACK))

                    #print(f'--->>> {t.has_flags(tcp.TCP_SYN)}'-'{t.has_flags(tcp.TCP_FIN)}'-'{t.has_flags(tcp.TCP_RST)}'-'{t.has_flags(tcp.TCP_ACK)}')
                    print(f'--->>> {t.has_flags(tcp.TCP_SYN)}, {t.has_flags(tcp.TCP_FIN)}, {t.has_flags(tcp.TCP_RST)}, {t.has_flags(tcp.TCP_ACK)}')
                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,         eth_dst=dst, eth_src=src,             ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,)            
                    
                    # Armazenar os dados extraidos do cabecalho UDP
                    cada_pacote = [dpid, in_port, data_hora, src, dst, srcip, dstip, protocol, -1, -1, u.src_port, u.dst_port, -1, -1, -1, -1, -1, ip.total_length, ip.ttl, -1, -1 ]


                    #cada_pacote = [data_hora, dpid, in_port, src, dst, srcip, dstip, protocol, u.src_port, u.dst_port  ]
                    # quebra de linha
                    cada_pacote.append('\n')


                    pkt_recebido = src + '-' + dst + '-' + srcip + '-' + dstip +'-' + str(protocol) +'-'+ str(u.src_port)+'-'+ str(u.dst_port)
                

                # Verificar se o pacote Packet In já foi visto anteriormente
                if pkt_recebido not in lista_pkt_recebidos:
                    lista_pkt_recebidos.append(pkt_recebido)

                    # Adicionar a variavel para compor o arquivo de coleta
                    if cada_pacote:
                        lista_global.append(cada_pacote)


                    print(f'Primeiro  - sw {origem} - pacote: {pkt_recebido}')

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, priority, match, actions)
        data = None


        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
