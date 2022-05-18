#!/usr/bin/python3

# Importar pandas
import pandas as pd

# Módulo de extração de caracteristicas
import feature_extraction

###################################################
# Caminho do arquivo que será realizado a EC
df = pd.read_csv('coleta_ddos_icmp.csv')

# Switch que está recebendo o tráfego
dpid = 1
# Porta que está recebendo o tráfego
in_port = 1
# Rótulo que será inserido no dataset
label = "DDoS_ICMP"

# Salvar no diretório atual o dataset criado
salvar_em_disco = True

##################################################
df.columns = ["sw","port","data_hora","src_mac","dst_mac","src_ip","dst_ip", "protocol", "port_src_tcp", "port_dst_tcp", "port_src_udp", "port_dst_udp", "TCP_SYN", "TCP_FIN", "TCP_RST", "TCP_ACK", "TCP_URG", "total_length", "ttl", "icmp_type", "icmp_code","deletar"]

# Realizar a Extração de Características
feature_extraction.f_extracao_caracteristicas(df, dpid, in_port, label, salvar_em_disco )

print('Dataset criado!')


