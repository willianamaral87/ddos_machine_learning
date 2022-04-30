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

lista_global = []


dic_pkts_time = {}
dic_pkts_cont = {}


dic_ml_ativador = {}

regra = 'original'


lista_pkt_recebidos = []


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        hub.spawn(self.myfunction)
        
        #hub.spawn(f_thread_teste)

    # Thread para salvar em um arquivo o conteudo da variavel V que contem o trafego de rede capturado no intervalo t 
    def myfunction(self):
        self.logger.info("")
        #seg = 1
        print(f'Carregando SO...')
        hub.sleep(15)
        print('iniciando a coleta...')
        seg = 0
        while True:
            
            self.logger.info("Tempo de coleta - %d", seg)
            seg = seg + 30

            if lista_global:
                string = ''
                for i in range (len(lista_global)):
                    for j in range (len(lista_global[i])):
                        string =  string + ','+   str(lista_global[i][j])   

                lista_global.clear()

                arquivo = open('dataset_udp.csv','w')
                arquivo.writelines(string)
                arquivo.close()
            hub.sleep(30)


    def f_thread_teste(self,dpid ):
        print(f'acessando thread teste')
        i = 0

        print('antes do hub')

        while(i <= 10):
            print(f'sw : {dpid} - i : {i}')
            i = i + 1
            hub.sleep(0.5)
        print('Finalizando thread...')

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


        #global ml_ativador


        # TESTE
        priority = 1 

        global lista_global

        global regra


        # Capturar data e hora do pacote recebido
        now = datetime.now()
        data_hora = (str(now.year)+'/'+str(now.month)+'/'+str(now.day) + ' ' + str(now.hour)+':'+str(now.minute)+':'+str(now.second))

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

                # Chamar a thread de ML
                #hub.spawn(self.f_thread_teste, dpid)


               # print(f'analisando: sw {dpid}')

                origem = 'sw'+str(dpid) + '-p' + str(in_port)


                ######################

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                    
                    # Armazenar os dados extraidos do cabecalho ICMP
                    cada_pacote = [dpid, in_port, data_hora, dpid, in_port, src, dst, srcip, dstip, protocol, -1, -1  ] 
                    # quebra de linha
                    cada_pacote.append('\n')
                    
                    # Verificar pacote único - não repetido
                    pkt_recebido = src + '-' + dst + '-' + srcip + '-' + dstip +'-' + str(protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,)

                    # Armazenar os dados extraidos do cabecalho TCP
                    cada_pacote = [data_hora, dpid, in_port, src, dst, srcip, dstip, protocol, t.src_port, t.dst_port, t.has_flags(tcp.TCP_SYN), t.has_flags(tcp.TCP_FIN), t.has_flags(tcp.TCP_RST), t.has_flags(tcp.TCP_ACK)  ]
                    # quebra de linha
                    cada_pacote.append('\n')

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
                


                if pkt_recebido not in lista_pkt_recebidos:
                    lista_pkt_recebidos.append(pkt_recebido)

                    print(f'Primeiro  - sw {origem} - pacote: {pkt_recebido}')

                    if origem not in dic_pkts_time :
                        #print(f'Primeiro  - sw {origem} - pacote: {pkt_recebido}')
                        dic_pkts_time[origem] = now
                        dic_pkts_cont[origem] = 1 #comeca a contar com um pacote
                        dic_ml_ativador[origem] = False
                    else:
                        dif = now - dic_pkts_time[origem]
                        
                        if dif.seconds >= 7:
                            dic_pkts_time.pop(origem)
                            dic_pkts_cont.pop(origem)
                            dic_ml_ativador.pop(origem)
                            regra = 'original'
                        else:
                            dic_pkts_cont[origem] =  dic_pkts_cont[origem] + 1

                            if dic_pkts_cont[origem] >= 10 :
                                if dic_ml_ativador[origem] == False:
                                    #if dpid in sw_acesso:
                                        print(f'ATIVANDO ML EM : {origem}')
                                        dic_ml_ativador[origem] = True
                                        regra = 'alterada'
                                        hub.spawn(self.f_thread_teste, dpid)
                                else:
                                    print(f'ML em execução... : {origem}')

              #  else:
              #      print(f'já está na lista - sw {origem} - pacote:  {pkt_recebido}')
                        
                if regra  == 'alterada':                

                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port)
                    out_port = 0
                    actions = [parser.OFPActionOutput(out_port)]

                    priority = 100

                    regra = 'original'


                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, priority, match, actions)
        data = None

        # Verificar se corresponde a um pacote contendo ICMP, TCP ou UDP
        if cada_pacote:
            #print(f'-->>> {cada_pacote}')
            lista_global.append(cada_pacote)




        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
