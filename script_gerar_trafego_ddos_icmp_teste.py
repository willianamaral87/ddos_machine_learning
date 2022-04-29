#! /usr/bin/env python3 

# Importar scapy (criar pacotes)
from scapy.all import * 

import time

# len=valor ; total length - cabeçalho IP

print('Iniciando ataque ICMP...')
print('Ataques com MAC de origem aleatório')

################# VARIAVEIS #################
n_repeticoes_cada_icmp = 1

############### GERAR ATAQUES ###############
def gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp  ):
    for pkt in n_pacotes:
        print(f'Tempo entre pacotes: {t}')
        print(f'Quantidade de pacotes: {pkt}')
    
        for i in range(n_repeticoes_cada_icmp):
            pkt_ping = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip)/ICMP()
            sendp(pkt_ping, inter=t, count = pkt  )
    
        print('-'*15)
        time.sleep(5)
    print('#'*30)
    time.sleep(20)
############################################

# Seleção de características
atributos = [ 1, 2, 3, 4, 5, 6, 7 ]

for atrib in atributos:
    if atrib == 1:
        print('1 - Somente com MAC de origem aleatório')
        src_mac = RandMAC()
        dst_mac = '00:00:00:00:00:04'
        src_ip = '10.0.0.1'
        dst_ip = '10.0.0.4'
    elif atrib == 2:
        print('2 - Somente com IP de origem aleatório')
        src_mac = '00:00:00:00:00:01'
        dst_mac = '00:00:00:00:00:04'
        src_ip = RandIP()
        dst_ip = '10.0.0.4'
    elif atrib == 3:
        print('3 - Somente com IP de destino aleatório')
        src_mac = '00:00:00:00:00:01'
        dst_mac = '00:00:00:00:00:04'
        src_ip = '10.0.0.1'
        dst_ip = RandIP()
    elif atrib == 4:
        print('4 - MAC de origem aleatório + IP de origem aleatório')
        src_mac = RandMAC()
        dst_mac = '00:00:00:00:00:04'
        src_ip = RandIP()
        dst_ip = '10.0.0.4'
    elif atrib == 5:
        print('5 - MAC de origem aleatório + IP de destino aleatório')
        src_mac = RandMAC()
        dst_mac = '00:00:00:00:00:04'
        src_ip = '10.0.0.1'
        dst_ip =  RandIP()
    elif atrib == 6:
        print('6 - IP de origem aleatório +  IP de destino aleatório')
        src_mac = '00:00:00:00:00:01'
        dst_mac = '00:00:00:00:00:04'
        src_ip = RandIP()
        dst_ip = RandIP()
    elif atrib == 7:
        print('7 - MAC de origem aleatório + IP de origem aleatório + IP de destino aleatório')
        src_mac = RandMAC()
        dst_mac = '00:00:00:00:00:04'
        src_ip = RandIP()
        dst_ip = RandIP()


    ############################################
    #tempo_entre_pacotes 
    t = 1
    # número de pacotes
    n_pacotes = [ 5, 10, 15, 20 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)

    ###########################################

    #tempo_entre_pacotes
    t = 0.7
    # número de pacotes
    n_pacotes = [ 5, 10, 15, 20, 25 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)

    ##########################################

    #tempo_entre_pacotes
    t = 0.5
    # número de pacotes
    n_pacotes = [ 5, 10, 15, 20, 25, 30 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)

    #######################################

    #tempo_entre_pacotes
    t = 0.3
    # número de pacotes
    n_pacotes = [ 5, 10, 15, 20, 30 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)

    #######################################

    #tempo_entre_pacotes
    t = 0.1
    # número de pacotes
    n_pacotes = [ 5, 25, 50, 75, 100 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)

    #######################################

    #tempo_entre_pacotes
    t = 0.08
    # número de pacotes
    n_pacotes = [ 10, 30, 60, 90, 120 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)

    #######################################

    #tempo_entre_pacotes
    t = 0.06    
    # número de pacotes
    n_pacotes = [ 10, 20, 50, 90, 120, 150 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)

    #######################################

    #tempo_entre_pacotes
    t = 0.04
    # número de pacotes
    n_pacotes = [ 5, 20, 40, 60, 80, 100, 120, 140, 160, 180, 200, 220 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)

    #######################################

    #tempo_entre_pacotes
    t = 0.02
    # número de pacotes
    n_pacotes = [ 10, 30, 60, 80, 120, 140, 160, 180, 200, 220, 240, 280, 320, 360, 380, 400, 420 ]
    gerar_ataque_icmp(t, n_pacotes, src_mac, src_ip, dst_ip, n_repeticoes_cada_icmp)
