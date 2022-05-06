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

# Pandas - Manipular dataframe
import pandas as pd

pd.set_option('display.max_columns', None)

# importar o módulo de Extração de Características
import feature_extraction

# Importar o módulo de detecção de DDoS
import detector_ddos

# 
import numpy as numpy

lista_global = []


dic_pkts_time = {}
dic_pkts_cont = {}


# Dicionário de controle de pacotes recebidos por switch e porta
dic_pkts = {}

dic_ml_ativador = {}

# Utilizado para alterar a regra default enviada aos switches
regra = 'original'

lista_pkt_recebidos = []

print('Treinando o Modelo')
modelo = detector_ddos.f_treinamento()
#print(modelo)
print('Modelo Treinado')


def f_teste(df_ec, dpid, in_port):


    # DESMARCAR OS COMENTÁRIOS PARA EXIBIR OS DATASETS INTERMEDIÁRIOS GERADOS


#-#    print(f'Dataset do tráfego coletado:')
#-#    print(df_ec)

    # Módulo de Extração de Características
    fe = feature_extraction.f_extracao_caracteristicas(df_ec, dpid, in_port)
#-#    print(f'Dataset com Extração de Características: ')
#-#    print(fe)

#-#    print('-'*20)

    #modelo = detector_ddos.f_treinamento()

    result_ml = detector_ddos.f_predicao(modelo, fe)

    print(f'RESULTADO MACHINE LEARNING: {result_ml}')

    if 'DDOS_ICMP' in result_ml:
        print(f'ATAQUE DETECTADO NO SWITCH {dpid} PORTA {in_port}')
        regra = 'alterada'
        return regra
    else:
        return


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        hub.spawn(self.myfunction)

    # Thread para salvar em um arquivo o conteudo da variavel V que contem o trafego de rede capturado no intervalo t 
    def myfunction(self):
        print(f'Carregando NOS...')
        
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


        # Prioridade da regra inserida na tabela do switch
        priority = 1 

        global lista_global

        global regra


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

                # A origem é composta pelo ID do switch juntamente com o ID da porta
                origem = 'sw'+str(dpid) + '-p' + str(in_port)

                ######################

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    # Capturar campos do protocolo ICMP
                    pi = pkt.get_protocol(icmp.icmp)

                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                    
                    # Armazenar os dados extraidos do cabecalho ICMP
                    #cada_pacote = [dpid, in_port, data_hora, dpid, in_port, src, dst, srcip, dstip, protocol, -1, -1  ] 
                    cada_pacote = [dpid, in_port, data_hora, src, dst, srcip, dstip, protocol, -1, -1, -1, -1, -1,-1,-1,-1, -1, ip.total_length, ip.ttl, pi.type, pi.code ] 


                    # quebra de linha
               #     cada_pacote.append('\n')
                    

                    #cada_pacote2 = [dpid, in_port, data_hora, dpid, in_port, src, dst, srcip, dstip, protocol, -1, -1  ]


                    # Verificar pacote único - não repetido
                    pkt_recebido = src + '-' + dst + '-' + srcip + '-' + dstip +'-' + str(protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,)

                    # Armazenar os dados extraidos do cabecalho TCP
                    cada_pacote = [data_hora, dpid, in_port, src, dst, srcip, dstip, protocol, t.src_port, t.dst_port, t.has_flags(tcp.TCP_SYN), t.has_flags(tcp.TCP_FIN), t.has_flags(tcp.TCP_RST), t.has_flags(tcp.TCP_ACK)  ]
                    # quebra de linha
           ###         cada_pacote.append('\n')

                    pkt_recebido = src + '-' + dst + '-' + srcip + '-' + dstip +'-' + str(protocol) +'-'+ str(t.src_port)+'-'+ str(t.dst_port)+'-'+ str(t.has_flags(tcp.TCP_SYN))+'-'+ str(t.has_flags(tcp.TCP_FIN))+'-'+ str(t.has_flags(tcp.TCP_RST))+'-'+ str(t.has_flags(tcp.TCP_ACK))

                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,)            
                    # Armazenar os dados extraidos do cabecalho UDP
                    print(protocol)
                    cada_pacote = [data_hora, dpid, in_port, src, dst, srcip, dstip, protocol, u.src_port, u.dst_port  ]
                    # quebra de linha
                    cada_pacote.append('\n')


                    pkt_recebido = src + '-' + dst + '-' + srcip + '-' + dstip +'-' + str(protocol) +'-'+ str(u.src_port)+'-'+ str(u.dst_port)
                

                # Analisar somente o pacote recebido na porta do host conectado
                # Utilizado para considerar somente o primeiro pacote recebido - que deve ser do switch que o host está conectado
                if pkt_recebido not in lista_pkt_recebidos:
                    lista_pkt_recebidos.append(pkt_recebido)

                    print(f'Pacote recebido em {origem} - campos {pkt_recebido}')
                    
                    # Realizar o controle dos pacotes recebidos por porta de switch
                    # Se o ID do switch + porta do switch não estiver na lista, então as variáveis são inicializadas
                    if origem not in dic_pkts_time :
                        dic_pkts_time[origem] = now        # Recebe timestamp atual 
                        dic_pkts_cont[origem] = 1          # Comeca a contar com um pacote
                        dic_ml_ativador[origem] = False    # ML não ativado
                        dic_pkts[origem] = []
                        dic_pkts[origem].append(cada_pacote)
                        #dic_pkts[origem].update(  cada_pacote )

                    else: # Se o pacote estiver estiver na lista - não for o primeiro pacote recebido do sw e porta do sw
                        # Calcular a diferença de tempo entre o pacote atual e o primeiro pacote recebido
                        dif = now - dic_pkts_time[origem]
                        
                        # Se a diferença de tempo for maior que 7 segundos, a origem (sw+porta) é removida das variaveis de controle.
                        # Pois passou muito tempo, e não teve evidências de ataques
                        if dif.seconds >= 12: #12
                            dic_pkts_time.pop(origem)
                            dic_pkts_cont.pop(origem)
                            dic_ml_ativador.pop(origem)
                 #           regra = 'original'              # Utilizar a regra original
                        else: # Se menor que o tempo especificado
                            # O contador da quantidade de pacote é incrementado (no sw e porta que recebeu o pacote)
                            dic_pkts_cont[origem] =  dic_pkts_cont[origem] + 1
                            
                            dic_pkts[origem].append(  cada_pacote )

                            # Se ultrapassar o threshold de X pacotes.
                            if dic_pkts_cont[origem] >= 5 : # 5 -10
                                # Verificar se o ML já está em execução. Se não tiver então é inicializado o ML no sw e porta

                                # Converter o dicionário ......... em dataframe
                                df_ec = pd.DataFrame(dic_pkts[origem])


                                # Alterar o nome das colunas
                                df_ec.columns = ["sw","port","data_hora","src_mac","dst_mac","src_ip","dst_ip", "protocol", "port_src_tcp", "port_dst_tcp", "port_src_udp", "port_dst_udp", "TCP_SYN", "TCP_FIN", "TCP_RST", "TCP_ACK", "TCP_URG", "total_length", "ttl", "icmp_type", "icmp_code"]


                                if dic_ml_ativador[origem] == False:
                                    print(f'ATIVANDO ML EM : {origem}')

                                    regra = f_teste( df_ec, dpid, in_port )

                                    # Limpando datasets
                                    del df_ec

                                    dic_ml_ativador[origem] = True
#-#                                else:
#-#                                    print(f'ML em execução... : {origem}')


                # Utilizado para inserir a regra na tabela do switch para negar o acesso a rede        
                if regra  == 'alterada':                

                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port)
                    out_port = 0     # Porta de saida inexistente - equivalente a null0 em Cisco
                    actions = [parser.OFPActionOutput(out_port)]
                    priority = 100   # Prioridade alta para ser analizada primeiro
                    regra = 'original'

                    print(f'COMANDO DE DESATIVAÇÃO DE PORTA ENVIADA AO SWITCH {dpid} PORTA {in_port}!')

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, priority, match, actions, msg.buffer_id, ofproto)
                    return
                else:
                    self.add_flow(datapath, priority, match, actions)
        data = None

        # Verificar se corresponde a um pacote contendo ICMP, TCP ou UDP
        if cada_pacote:
            lista_global.append(cada_pacote)

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
