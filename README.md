## Instruções de uso dos scripts ##

### Criar o dataset - coleta de dados

#### Controlador Ryu

Primeiramente é necessário executar o controlador Ryu para realizar a coleta do tráfego. O script utilizado é o l4_switch_criar_dataset.py.

Na linha 80 é necessário informar o nome do arquivo que será criado:

arquivo = open('*nome_do_arquivo.csv*','a')

Se não alterado, o nome padrão é 'coleta_trafego.csv'. Deve ser alterado para cada tipo de coleta.

Executar Ryu (criar o dataset): 
ryu-manager l4_switch_criar_dataset.py

#### Criar a topologia e gerar o tráfego de rede:

- Para tráfego normal ICMP: 

  - A topologia deve conter no mínimo 510 hosts, é sugerido utilizar a topologia (economia computacional):

    sudo mn --controller=remote,ip=127.0.0.1 --mac --topo=single,510
  
    Executar o script: python3 script_gerar_trafego_icmp.py no host 1 (origem)
  
  - Utilizar o comando pingall com diversas topologias

- Para tráfego DDoS ICMP:  

  Pode ser utilizado qualquer topologia para gerar o ataque DDoS ICMP. Topologia utilizada:
  
  sudo mn --controller=remote,ip=127.0.0.1 --mac --topo=single,4 --switch=ovs
  
  Realizar o comando pingall para realizar o mapeamento ARP (após carregar a topologia)
  
  Executar o script: python3 script_gerar_trafego_ddos_icmp.py para gerar o ataque
  
  Após finalizar a coleta, remover as linhas do arquivo adicionadas pelo comando pingall



Para ambos os scripts: após carregar a topologia, utilizar o comando xterm h1 e rodar os scripts.

Obs.: É utilizado o host h1 pois outros scripts já realizam a EC baseado no switch 1 porta 1, porém pode ser alterado.

#--------------------------------------------------------------------------------------------------------------#

#### Criar o dataset - Extração de Características

Desenvolvido o script *feature_extraction_criar_dataset.py* para realizar a Extração de Características do tráfego de rede coletado na etapa anterior.

Alguns dados devem ser alterados no script (conforme cada tipo de tráfego):

Caminho do arquivo de entrada - que será realizado a EC

dpid = 1 # Identificação do switch que foi gerado o tráfego

in_port = 1 # Identificação da porta que foi gerado o tráfego

label = "ICMP" OU "DDoS_ICMP" # Rótulo do Dataset 

Para cada arquivo gerado na etapa anterior, é necessário realizar a extração de características, utilizando o script *feature_extraction_criar_dataset.py*.

OBS.: Na fase de predição do tráfego, o rótulo é ignorado. 


#--------------------------------------------------------------------------------------------------------------#

#### Criar o dataset - Concatenar os arquivos 
Os arquivos gerados na fase de Extração de Características devem ser concatenados em um único arquivo para criar o dataset final.

Utilizar o script: *concatenar_arquivos.py*

Os dataset gerados na etapa de EC devem ser informados neste script, assim como o nome do dataset final que será gerado.

#--------------------------------------------------------------------------------------------------------------#

### Detecção de tráfego no controlador Ryu

Executar a topologia SDN para detecção de tráfego ICMP e DDoS_ICMP

ryu-manager l4_switch_detector_oficial.py

Depende de:

- feature_extraction.py

- detector_ddos.py

- dataset que será realizado no treinado / predição

Topologia: sudo mn --controller=remote,ip=127.0.0.1 --mac --topo=tree,depth=3,fanout=2 --switch=ovs --nat --ipbase=172.16.20.0/23

#--------------------------------------------------------------------------------------------------------------#

#### Gerar tráfego normal ICMP

pingall

ping <ip>

#### Tráfego DDoS ICMP

Utilizar scapy com opções:
  - RandMAC() : gerar MAC aleatório
  - RandIP()  : gerar IP aleatório
  
pkt_ping = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip)/ICMP()
  
sendp(pkt_ping, inter=intervalo_entre_pacotes, count = qde_pacotes)

# No momento utilizar somente o IP de origem ou destino aleatório em DDoS Ataque - verificar os MACs
# Terminar a programação dos MACs para reconhecer os MACs no detector
