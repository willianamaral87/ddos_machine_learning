#!/usr/bin/env python

import pandas as pd

# Dataset 1
df_1 = pd.read_csv('dataset_ICMP.csv')

# Dataset 2 
df_2 = pd.read_csv('dataset_DDoS_ICMP.csv')
# df_3 = pd.read_csv('dataset_trafego_ddos_icmp_t3.csv')
# df_4 = pd.read_csv('dataset_trafego_ddos_icmp_t4.csv')

# pd.set_option('display.max_rows', None)
# pd.set_option('display.max_columns', None)

#############################

#############################

# df_3, df_4

df_dataset = pd.concat([df_1, df_2 ])

# Deletar a coluna
df_dataset.drop('Unnamed: 0',axis=1,inplace=True)

# Remover valores duplicados
df_dataset = df_dataset.drop_duplicates()

nome_dataset = "dataset_final_gerado.csv"
# Salvar o dataset criado em arquivo
df_dataset.to_csv(nome_dataset)

print(f'Dataset salvo com nome: {nome_dataset}')
