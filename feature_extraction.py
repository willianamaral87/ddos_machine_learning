#!/usr/bin/python3

# Script utilizado para realizar a extração de caracteristicas
# o arquivo de entrada deve ter o campo ID - inserido via excel

# Intervalo de tempo utilizado para realizar a extração de caracteristicas
from datetime import timedelta

# Calcular a entropia
from scipy.stats import entropy

# Manipular os dataframes
import pandas as pd

# pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)

# Calculo das quantidades dos marcadores TCP
def f_soma_tcp_syn(df_aux):
    return df_aux['TCP_SYN'].sum()

def f_soma_tcp_fin(df_aux):
    return df_aux['TCP_FIN'].sum()

def f_soma_tcp_rst(df_aux):
    return df_aux['TCP_RST'].sum()

def f_soma_tcp_ack(df_aux):
    return df_aux['TCP_ACK'].sum()

def f_soma_tcp_urg(df_aux):
    return df_aux['TCP_URG'].sum()

# Relação entre o número de pacotes ICMP e o total
def f_ratio_icmp_total(df_aux_icmp, df_aux_tcp, df_aux_udp):
    return df_aux_icmp['protocol'].count() / (df_aux_icmp['protocol'].count() + 
                                   df_aux_tcp['protocol'].count() + 
                                   df_aux_udp['protocol'].count())

# Relação entre o número de pacotes TCP e o total
def f_ratio_tcp_total(df_aux_icmp, df_aux_tcp, df_aux_udp):
    return df_aux_tcp['protocol'].count() / (df_aux_icmp['protocol'].count() + 
                                   df_aux_tcp['protocol'].count() + 
                                   df_aux_udp['protocol'].count())

# Relação entre o número de pacotes UDP e o total
def f_ratio_udp_total(df_aux_icmp, df_aux_tcp, df_aux_udp):
    return df_aux_udp['protocol'].count() / (df_aux_icmp['protocol'].count() + 
                                   df_aux_tcp['protocol'].count() + 
                                   df_aux_udp['protocol'].count())

# Calcular valor mínimo
def f_calc_min(df_aux):
    
    if df_aux.shape[0] == 0:
        return -1
    else:
        return df_aux['total_length'].min()

# Calcular valor máximo do total length
def f_calc_max(df_aux):
    
    if df_aux.shape[0] == 0:
        return -1
    else:
        return df_aux['total_length'].max()

# Calcular a media do total length
def f_calc_media(df_aux):
    if df_aux.shape[0] == 0:
        return -1
    else:
        return df_aux['total_length'].mean()

# Calcular a mediana do total length
def f_calc_mediana(df_aux):
    if df_aux.shape[0] == 0:
        return -1
    else:
        return df_aux['total_length'].median()

# Calcular o desvio padrão do total length
def f_calc_desvio_padrao(df_aux):
    if df_aux.shape[0] == 0 or df_aux.shape[0] == 1:
        return -1
    else:
        return df_aux['total_length'].std()

# Calcular o somatório do total length
def f_calc_soma(df_aux):
    if df_aux.shape[0] == 0:
        return -1
    else:
        return df_aux['total_length'].sum()

# Função para calcular a entropia
# recebe como parâmetro uma lista
def f_calc_entropia(l_amostras):
    
    #print('inicio entropia')
    # Total de amostras
    total_amostras = len(l_amostras)
    #print(f'Total de amostras: {total_amostras}')

    # Total de amostras únicas
    total_amostras_unicas = len(set(l_amostras))
    #print(f'Total de amostras únicas: {total_amostras_unicas}')

    # Conjunto de amostras únicas
    amostras_unicas = list(set(l_amostras))
    #print(amostras_unicas)

    # Valores =de cálculo da entropia
    valores = []

    # Utilizado para obter a quantidade de amostras por "classe"
    for i in range (total_amostras_unicas):
        valores.append( l_amostras.count(amostras_unicas[i]))
   
    #print(f'Total de amostras unicas : {total_amostras_unicas} antes')
    # Utilizado quando a quantidades de amostras é igual a 1.
    if total_amostras_unicas == 1 or total_amostras_unicas == 0: 
        total_amostras_unicas = 2

    #print(f'Total de amostras unicas : {total_amostras_unicas} depois')
    #print('X--------X')
    # Calculo da entropiaa
    #print(f'Valores:  {valores}')
    #print(f' Total Amostras unicas : {total_amostras_unicas} ')
    e = entropy(valores, base = total_amostras_unicas, )
    
    #e = 10
    #print('fim entropia')

    return abs(e)

# Calculo do total de pacotes
def f_calc_total_pkts(df_aux, dpid):
    q_total_pkts = df_aux[df_aux['sw']==dpid]['sw'].count()
    return q_total_pkts

# Calculo da quantidade de pacotes por protocolo
def f_calc_q_pkts_por_protocolo(df):

    # Agrupar utilizando o critério procolo
    q_pkts_por_protocolo = df.groupby('protocol').groups

    # Capturar a quantidade de pacotes por protocolo
    # Senão encontrado retorna 0
    if 1 in q_pkts_por_protocolo:
        q_pkts_icmp = q_pkts_por_protocolo[1].shape[0]
    else:
        q_pkts_icmp = 0

    if 6 in q_pkts_por_protocolo:
        q_pkts_tcp = q_pkts_por_protocolo[6].shape[0]
    else:
        q_pkts_tcp = 0

    if 17 in q_pkts_por_protocolo:
        q_pkts_udp = q_pkts_por_protocolo[17].shape[0]
    else:
        q_pkts_udp = 0
    return q_pkts_icmp, q_pkts_tcp, q_pkts_udp

# Calcular o intervalo
def calc_intervalo(df_aux):
    calc_intervalo  = []
    
   # print(f'Quantidade de linhas: {df_aux.shape[0]}')

    for i in range(1,df_aux.shape[0]):
        calc = (df_aux['data_hora'].iloc[i] - df_aux['data_hora'].iloc[i-1]).total_seconds()
#-#        print(f"Intervalo entre {df_aux['data_hora'].iloc[i]} e {df_aux['data_hora'].iloc[i-1]} é {calc}" )
        calc_intervalo.append(calc)
    media = sum(calc_intervalo)/len(calc_intervalo)
    return media

# Calcular o tempo médio entre os pacotes
def calc_intervalo_medio_entre_pkts(df_aux):
    #print('---** DF Recebido ** ---')
    #print(df_aux)
    #print('-- ** FIM DF Recebido ** ---')
    q_pkts_por_protocolo = df_aux.groupby('protocol').groups

    # Capturar a quantidade de pacotes por protocolo
    # Senão encontrado retorna 0
    
    ##############################################
    if 1 in q_pkts_por_protocolo:
        q_pkts_icmp = q_pkts_por_protocolo[1].shape[0]
                
        if q_pkts_icmp == 0 or q_pkts_icmp == 1:
            tempo_medio_icmp = -1
        elif q_pkts_icmp >= 2:
            tempo_medio_icmp = calc_intervalo(df_aux)
    else:
        q_pkts_icmp = 0

    ##############################################
    if 6 in q_pkts_por_protocolo:
        q_pkts_tcp = q_pkts_por_protocolo[6].shape[0]
              
        if q_pkts_tcp == 1:
            tempo_medio_tcp = -1
        elif q_pkts_tcp >= 2:
            tempo_medio_tcp = calc_intervalo(df_aux)         
    else:
        q_pkts_tcp = 0
        tempo_medio_tcp = -1

    ##############################################
    if 17 in q_pkts_por_protocolo:
        q_pkts_udp = q_pkts_por_protocolo[17].shape[0]
                       
        if q_pkts_udp == 1:
            tempo_medio_udp = -1
        elif q_pkts_udp >= 2:
            #print(df_aux)
            tempo_medio_udp = calc_intervalo(df_aux)
    else:
        q_pkts_udp = 0
        tempo_medio_udp = -1
   
    return tempo_medio_icmp, tempo_medio_tcp, tempo_medio_udp

# Calcular valores distintos / total de amostras únicas
def f_calc_valores_distintos(l_amostras):
    
    # Total de amostras
    total_amostras = len(list(l_amostras))

    # Total de amostras únicas
    total_amostras_unicas = len(set(l_amostras))
    
    return total_amostras_unicas


# Realizar a extração de caracteristicas
def f_extracao_caracteristicas(df, dpid, in_port, label, salvar):
    
    # Converter tipo de object para datetime
    df['data_hora'] = df['data_hora'].astype('datetime64[ns]')

    # Dataset final
    result = []
    
    for cont_tempo in range(1,11):
        # Intervalo em segundos do calculo
        tempo_calculo = cont_tempo
#-#        print('-'*35)
#-#        print(f'INTERVALO -> {tempo_calculo}')
        
        # Contador para determinar o fim do loop
        cont = 0

        # Tempo inicial da EC
        dh_inicio = df['data_hora'][0]
        dh_fim = df['data_hora'][0] + timedelta(seconds = tempo_calculo)

        while True:
#-#            print(f'TEMPO INICIO: {dh_inicio}')
#-#            print(f'TEMPO FIM   : {dh_fim}')


            df_aux = df[(df['data_hora'] >= dh_inicio ) & (df['data_hora'] < dh_fim ) & (df['sw'] == dpid) & (df['port'] == in_port)]
#-#            print('---DF AUX---')
#-#            print(df_aux)
#-#            print('------------')
            # Verificar se existe valor no novo dataframe
            if not df_aux.index.empty:
                ######### Separar os protocolos em dataframes diferentes #########
                # Dataframe ICMP
                df_aux_icmp = df_aux[df_aux['protocol'] == 1]

                # Dataframe TCP
                df_aux_tcp = df_aux[df_aux['protocol'] == 6]

                # Dataframe UDP
                df_aux_udp = df_aux[df_aux['protocol'] == 17]

                ######### Entropia MAC de origem #########     
                # Entropia MAC de origem - protocolo ICMP
                e_src_mac_icmp = f_calc_entropia(list(df_aux_icmp['src_mac']))

                # Entropia MAC de origem - protocolo ICMP
                e_src_mac_tcp = f_calc_entropia(list(df_aux_tcp['src_mac']))

                # Entropia MAC de origem - protocolo UDP
                e_src_mac_udp = f_calc_entropia(list(df_aux_udp['src_mac']))

                ######### Entropia IP de origem #########
                # Entropia IP de origem - protocolo ICMP
                e_src_ip_icmp = f_calc_entropia(list(df_aux_icmp['src_ip']))

                # Entropia MAC de origem - protocolo ICMP
                e_src_ip_tcp = f_calc_entropia(list(df_aux_tcp['src_ip']))

                # Entropia MAC de origem - protocolo UDP
                e_src_ip_udp = f_calc_entropia(list(df_aux_udp['src_ip']))

                ######### Entropia MAC de destino #########     
                # Entropia MAC de destino - protocolo ICMP
                e_dst_mac_icmp = f_calc_entropia(list(df_aux_icmp['dst_mac']))

                # Entropia MAC de origem - protocolo ICMP
                e_dst_mac_tcp = f_calc_entropia(list(df_aux_tcp['dst_mac']))

                # Entropia MAC de origem - protocolo UDP
                e_dst_mac_udp = f_calc_entropia(list(df_aux_udp['dst_mac']))

                ######### Entropia IP de destino #########
                # Entropia IP de origem - protocolo ICMP
                e_dst_ip_icmp = f_calc_entropia(list(df_aux_icmp['dst_ip']))

                # Entropia MAC de origem - protocolo ICMP
                e_dst_ip_tcp = f_calc_entropia(list(df_aux_tcp['dst_ip']))

                # Entropia MAC de origem - protocolo UDP
                e_dst_ip_udp = f_calc_entropia(list(df_aux_udp['dst_ip']))

                ######### Quantidade de pacotes #########
                # Calcular total de pacotes
                q_total_pkts = f_calc_total_pkts(df_aux, dpid)

                # Calcular a quantidade de pacotes por protocolo
                q_pkts_icmp, q_pkts_tcp, q_pkts_udp = f_calc_q_pkts_por_protocolo(df_aux)

                # Calcular tempo médio entre os pacotes
                tempo_medio_icmp, tempo_medio_tcp, tempo_medio_udp = calc_intervalo_medio_entre_pkts(df_aux)

                ######### Valor distinto MAC de origem #########
                valor_distinto_mac_src_icmp = f_calc_valores_distintos(df_aux_icmp['src_mac'])
                valor_distinto_mac_src_tcp = f_calc_valores_distintos(df_aux_tcp['src_mac'])
                valor_distinto_mac_src_udp = f_calc_valores_distintos(df_aux_udp['src_mac'])

                ######### Valor distinto IP de origem #########
                valor_distinto_ip_src_icmp = f_calc_valores_distintos(df_aux_icmp['src_ip'])
                valor_distinto_ip_src_tcp = f_calc_valores_distintos(df_aux_tcp['src_ip'])
                valor_distinto_ip_src_udp = f_calc_valores_distintos(df_aux_udp['src_ip'])

                ######### Valor distinto MAC de destino ######### 
                valor_distinto_mac_dst_icmp = f_calc_valores_distintos(df_aux_icmp['dst_mac'])     
                valor_distinto_mac_dst_tcp = f_calc_valores_distintos(df_aux_tcp['dst_mac'])
                valor_distinto_mac_dst_udp = f_calc_valores_distintos(df_aux_udp['dst_mac'])

                ######### Valor distinto IP de destino #########
                valor_distinto_ip_dst_icmp = f_calc_valores_distintos(df_aux_icmp['dst_ip'])
                valor_distinto_ip_dst_tcp = f_calc_valores_distintos(df_aux_tcp['dst_ip'])
                valor_distinto_ip_dst_udp = f_calc_valores_distintos(df_aux_udp['dst_ip'])    

                ######### Calculo Total Length ICMP #########
                total_length_soma_icmp = f_calc_soma(df_aux_icmp)
                total_length_min_icmp = f_calc_min(df_aux_icmp)
                total_length_max_icmp = f_calc_max(df_aux_icmp)
                total_length_media_icmp = f_calc_media(df_aux_icmp)
                total_length_mediana_icmp = f_calc_mediana(df_aux_icmp)
                total_length_desvio_padrao_icmp = f_calc_desvio_padrao(df_aux_icmp)

                ######### Calculo Total Length TCP #########
                total_length_soma_tcp = f_calc_soma(df_aux_tcp)
                total_length_min_tcp = f_calc_min(df_aux_tcp)
                total_length_max_tcp =f_calc_max(df_aux_tcp)
                total_length_media_tcp = f_calc_media(df_aux_tcp)
                total_length_mediana_tcp = f_calc_mediana(df_aux_tcp)
                total_length_desvio_padrao_tcp = f_calc_desvio_padrao(df_aux_tcp)

                ######### Calculo Total Length UDP #########
                total_length_soma_udp = f_calc_soma(df_aux_udp)
                total_length_min_udp = f_calc_min(df_aux_udp)
                total_length_max_udp =f_calc_max(df_aux_udp)
                total_length_media_udp = f_calc_media(df_aux_udp)
                total_length_mediana_udp = f_calc_mediana(df_aux_udp)
                total_length_desvio_padrao_udp = f_calc_desvio_padrao(df_aux_udp)

                ######### Entropia TCP #########         
                e_src_port_tcp = f_calc_entropia(list(df_aux_tcp['port_src_tcp']))
                e_dst_port_tcp = f_calc_entropia(list(df_aux_tcp['port_dst_tcp']))

                ######### Entropia UDP #########         
                e_src_port_udp = f_calc_entropia(list(df_aux_udp['port_src_udp']))
                e_dst_port_udp = f_calc_entropia(list(df_aux_udp['port_dst_udp']))

                ######### Valor distinto Porta TCP #########
                valor_distinto_src_port_tcp = f_calc_valores_distintos(df_aux_tcp['port_src_tcp'])
                valor_distinto_dst_port_tcp = f_calc_valores_distintos(df_aux_tcp['port_dst_tcp'])

                ######### Valor distinto Porta UDP #########
                valor_distinto_src_port_udp = f_calc_valores_distintos(df_aux_udp['port_src_udp'])
                valor_distinto_dst_port_udp = f_calc_valores_distintos(df_aux_udp['port_dst_udp'])

                ######### Marcações TCP #########
                soma_tcp_syn = f_soma_tcp_syn(df_aux_tcp)
                soma_tcp_fin = f_soma_tcp_fin(df_aux_tcp)
                soma_tcp_rst = f_soma_tcp_rst(df_aux_tcp)
                soma_tcp_ack = f_soma_tcp_ack(df_aux_tcp)
                soma_tcp_urg = f_soma_tcp_urg(df_aux_tcp)

                ######### Entropia TTL - protocolo ICMP #########
                e_ttl_icmp = f_calc_entropia(list(df_aux_icmp['ttl']))
                e_ttl_tcp = f_calc_entropia(list(df_aux_tcp['ttl']))
                e_ttl_udp = f_calc_entropia(list(df_aux_udp['ttl']))

                ######### Valor distinto Porta TCP #########
                valor_distinto_ttl_icmp = f_calc_valores_distintos(df_aux_icmp['ttl'])
                valor_distinto_ttl_tcp = f_calc_valores_distintos(df_aux_tcp['ttl'])
                valor_distinto_ttl_udp = f_calc_valores_distintos(df_aux_udp['ttl'])


                ######### Relação entre protocolo e o total #########
                ratio_icmp_total = f_ratio_icmp_total(df_aux_icmp, df_aux_tcp, df_aux_udp)

                ratio_tcp_total = f_ratio_tcp_total(df_aux_icmp, df_aux_tcp, df_aux_udp)

                ratio_udp_total = f_ratio_udp_total(df_aux_icmp, df_aux_tcp, df_aux_udp)

                # Lista contendo a Extração de Caracteristicas 
                result.extend([[e_src_mac_icmp, e_src_mac_tcp, e_src_mac_udp, e_src_ip_icmp, e_src_ip_tcp, e_src_ip_udp,
                            e_dst_mac_icmp, e_dst_mac_tcp, e_dst_mac_udp, e_dst_ip_icmp, e_dst_ip_tcp, e_dst_ip_udp,
                            q_total_pkts, q_pkts_icmp, q_pkts_tcp, q_pkts_udp,  
                            tempo_medio_icmp, 
                            tempo_medio_tcp, tempo_medio_udp, valor_distinto_mac_src_icmp, valor_distinto_mac_dst_icmp ,
                            valor_distinto_mac_src_tcp, valor_distinto_mac_dst_tcp, 
                            valor_distinto_mac_src_udp, valor_distinto_mac_dst_udp,
                            valor_distinto_ip_src_icmp, valor_distinto_ip_dst_icmp, valor_distinto_ip_src_tcp, valor_distinto_ip_dst_tcp,
                            valor_distinto_ip_src_udp, valor_distinto_ip_dst_udp, 
                            total_length_min_icmp, total_length_max_icmp, total_length_media_icmp, total_length_mediana_icmp, total_length_desvio_padrao_icmp, 
                            total_length_soma_icmp, 
                            total_length_min_tcp, total_length_max_tcp, total_length_media_tcp, total_length_mediana_tcp, total_length_desvio_padrao_tcp, 
                            total_length_soma_tcp, 
                            total_length_min_udp, total_length_max_udp, total_length_media_udp, total_length_mediana_udp, total_length_desvio_padrao_udp, 
                            total_length_soma_udp,
                            e_src_port_tcp, e_dst_port_tcp, e_src_port_udp, e_dst_port_udp,
                            valor_distinto_src_port_tcp, valor_distinto_dst_port_tcp, valor_distinto_src_port_udp, valor_distinto_dst_port_udp,
                            soma_tcp_syn, soma_tcp_fin, soma_tcp_rst, soma_tcp_ack, soma_tcp_urg,
                            e_ttl_icmp, e_ttl_tcp, e_ttl_udp,
                            valor_distinto_ttl_icmp, valor_distinto_ttl_tcp, valor_distinto_ttl_udp,
                            ratio_icmp_total, ratio_tcp_total, ratio_udp_total,
                            label,
                            ]])

            # Inicio e fim da análise
            dh_inicio = dh_fim
            dh_fim = dh_fim  + timedelta(seconds = tempo_calculo)

            if df_aux.index.any():
                if df['data_hora'].iloc[-1] == df_aux['data_hora'].iloc[-1]:
                    #print(f'count is : {cont}')
                    break

            # Contagem para quebrar o loop
            cont += 1    
            if cont == 300:
                print('parou - atingiu 300 iterações')
                break

#########################################################################################33
    # Converter uma lista em dataframe
    dataset_result = pd.DataFrame(result)
    
    if dataset_result.shape[0] != 0:
        # Colocar nomes nas colunas do dataframe
        dataset_result.columns = ['en_src_mac_icmp', 'en_src_mac_tcp', 'en_src_mac_udp','en_src_ip_icmp', 'en_src_ip_tcp', 'en_src_ip_udp','en_dst_mac_icmp', 
                                'en_dst_mac_tcp', 'en_dst_mac_udp','en_dst_ip_icmp', 'en_dst_ip_tcp', 'en_dst_ip_udp', 
                              'q_total_pkts', 'q_pkts_icmp', 'q_pkts_tcp', 'q_pkts_udp',  
                              'tempo_medio_icmp', 'tempo_medio_tcp', 'tempo_medio_udp', 
                               'valor_distinto_mac_src_icmp', 'valor_distinto_mac_dst_icmp',
                              'valor_distinto_mac_src_tcp', 'valor_distinto_mac_dst_tcp',
                              'valor_distinto_mac_src_udp', 'valor_distinto_mac_dst_udp',
                              'valor_distinto_ip_src_icmp', 'valor_distinto_ip_dst_icmp', 
                              'valor_distinto_ip_src_tcp', 'valor_distinto_ip_dst_tcp', 
                              'valor_distinto_ip_src_udp', 'valor_distinto_ip_dst_udp',
                              'total_length_min_icmp', 'total_length_max_icmp', 'total_length_media_icmp', 'total_length_mediana_icmp', 'total_length_desvio_padrao_icmp', 
                              'total_length_soma_icmp',
                              'total_length_min_tcp', 'total_length_max_tcp', 'total_length_media_tcp', 'total_length_mediana_tcp', 'total_length_desvio_padrao_tcp', 
                              'total_length_soma_tcp',
                              'total_length_min_udp', 'total_length_max_udp', 'total_length_media_udp', 'total_length_mediana_udp', 'total_length_desvio_padrao_udp', 
                              'total_length_soma_udp', 'e_src_port_tcp', 'e_dst_port_tcp', 'e_src_port_udp', 'e_dst_port_udp',
                              'valor_distinto_src_port_tcp', 'valor_distinto_dst_port_tcp', 'valor_distinto_src_port_udp', 'valor_distinto_dst_port_udp',
                              'soma_tcp_syn', 'soma_tcp_fin', 'soma_tcp_rst', 'soma_tcp_ack', 'soma_tcp_urg',
                              'e_ttl_icmp', 'e_ttl_tcp', 'e_ttl_udp',
                              'valor_distinto_ttl_icmp', 'valor_distinto_ttl_tcp', 'valor_distinto_ttl_udp',
                              'ratio_icmp_total', 'ratio_tcp_total', 'ratio_udp_total',
                             'rótulo',
                              ]

        # Remover registros duplicados
        dataset_normal = dataset_result.drop_duplicates()
#        dataset_normal = dataset_result.copy()
        # Salvar o dataset em disco
        
        if salvar:
            dataset_normal.to_csv("dataset_"+ label +".csv")
            print(dataset_normal)
        else:
            return dataset_normal

    else:
        return print("ERRO!")
#f_extracao_caracteristicas(df)

