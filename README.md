## Instruções de uso dos scripts ##

### Criar o dataset

#### Controlador Ryu

Primeiramente é necessário executar o controlador Ryu para realizar a coleta do tráfego. O script utilizado é o l4_switch_criar_dataset.py.

Na linha 80 é necessário informar o nome do arquivo que será criado:

arquivo = open('*nome_do_arquivo.csv*','a')

#### Criar a topologia e gerar o tráfego de rede:

- Para tráfego normal ICMP: 

  A topologia deve conter no mínimo 510 hosts, é sugerido utilizar a topologia (economia computacional):

  sudo mn --controller=remote,ip=127.0.0.1 --mac --topo=single,510
  
  Executar o script: python3 script_gerar_trafego_icmp.py

- Para tráfego DDoS ICMP:  

  Pode ser utilizado qualquer topologia para gerar o ataque DDoS ICMP. Topologia utilizada:
  
  sudo mn --controller=remote,ip=127.0.0.1 --mac  --topo=tree,depth=3,fanout=2
  
  Realizar o comando pingall para realizar o mapeamento ARP (após carregar a topologia)
  
  Executar o script: python3 script_gerar_trafego_ddos_icmp.py para gerar o ataque
  
  Após finalizar a coleta, remover as linhas do arquivo adicionadas pelo comando pingall



Para ambos os scripts: após carregar a topologia, utilizar o comando xterm h1 e rodar os scripts.

#----------------------------------------------------------------------------------#

Realizar a extração de características
Utilizar o script feature_extraction_criar_dataset.py para realizar a conversão de cada arquivo de tráfego coletado.

Informar no  “feature_extraction_criar_dataset.py” o nome do arquivo que será realizado a extração de característica.

O nome do rótulo também deve ser informado no arquivo feature_extraction.py nas linhas 439 e 484. 
Pesquisar por: cat -n feature_extraction.py | grep 'rotulo' e cat -n feature_extraction.py | grep 'rótulo'

Para cada arquivo gerado na etapa anterior, é necessário realizar a extração de características.

OBS.: Na fase de predição do tráfego, o rótulo é ignorado. 
É necessário especificar o rótulo na fase de extração de características

#----------------------------------------------------------------------------------#

Concatenar os arquivos 
Os arquivos gerados na extração de características devem ser concatenados em um único arquivo para criar o dataset final.

Dependência:
feature_extraction.py

#----------------------------------------------------------------------------------#

Executar a topologia SDN para detecção de tráfego ICMP e DDoS_ICMP
ryu-manager l4_switch_detector_oficial.py

Depende de:
feature_extraction.py
detector_ddos.py
dataset_final_mod_2.csv
