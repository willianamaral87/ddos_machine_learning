# rodar no terminal :  "python3 monitorar_cpu_ryu.py pid_do_controller_ryu"

# Como obter o pid.
# - utilizar o comando ps -aux | grep ryu

# O conteudo será salvo em um arquivo de texto e será exibido na tela

# Sugestao de melhoria:
# - Salvar data / hora e rótulo (ddos ou normal) para criar gráfico
#   rótulo pode ser utilizado da saída do script do ryu

# Biblioteca utilizada para recuperar informações sobre processos em execução e utilização do sistema (CPU, memória, discos, rede, sensores).
import psutil 

# Funcao de tempo - controlar o sleep
import time

# Manipular diferentes partes do Python Runtime Environment. 
import sys  

# Obter o pid do ryu-manager  
pid = psutil.Process(int(sys.argv[1]))
	
print('O consumo de CPU será exibido na tela e salvo no arquivo de texto cpu_history_ryu.txt')
print('O tempo entre cada coleta é de 1 segundo por padrão')

while True: 	
    cpu = pid.cpu_percent()
    print(f'{cpu}')
    arquivo = open("cpu_history_ryu.txt", "a+")
    arquivo.write(str(cpu) + "\n")
    time.sleep(1)
arquivo.close()
