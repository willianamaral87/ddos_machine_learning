# rodar no terminal :  "python3 monitorar_cpu_ryu.py pid_do_controller_ryu"

# Como obter o pid.
# - utilizar o comando ps -aux | grep ryu

# O conteudo será salvo em um arquivo de texto e será exibido na tela

import psutil 
import time 
import sys  
#get pid of running ryu-manager  
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
