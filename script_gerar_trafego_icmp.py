# Executar comandos no Linux
import subprocess
# Tempo do sleep
import time
# Tempo de data hora
from datetime import datetime

# Data hora inicio
inicio = datetime.now()

# Intervalo em segundos entre cada pacote
intervalo = [ 0.5, 0.7, 1, 1.5, ]

#intervalo = [ 1, 3, 5 , 7]

# Endereço IP inicial do terceiro octecto
terceiro_octeto = 0
# Endereço IP inical do quarto octeto
quarto_octeto = 1

# Quantidade de hosts por envio
q_hosts = [ 5, 10, 15, 20, 25, 30 ]

# Para cada intervalo
for inter in intervalo:
    # Para cada quantidade de hosts dentro do intervalo
    for q_host in q_hosts: 
        print(f'INTERVALO ENTRE OS PACOTES: {inter}')   
        print(f'QUANTIDADE DE HOSTS: {q_host}')
        # Realizar o ping para cada host de destino dentro do intervalo
        for cont in range(q_host):
            # executar o comando
            saida = subprocess.check_output(["ping","-c","1","10.0."+str(terceiro_octeto)+"."+ str(quarto_octeto)   ])
            # imprimir a saida do ping
            print(saida)
            
            # incrementar um IP
            quarto_octeto += 1

            # Resetar o quarto octecto para 1
            # Incrementar 1 no terceiro octecto
            if quarto_octeto == 254 and terceiro_octeto == 0:
                terceiro_octeto = 1
                quarto_octeto = 1

            # intervalo entre cada ping
            time.sleep(inter)
        # Espaço de tempo entre cada sequencia
        time.sleep(10)

# Data hora fim
fim = datetime.now()
# Calcular o tempo em execução
dif = fim - inicio
tempoExec = dif.total_seconds() 

print("Levou %.10f segundos para rodar " % tempoExec)
print('Script executado com sucesso!')
