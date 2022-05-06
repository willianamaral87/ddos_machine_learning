#!/usr/bin/python3

# Importar pandas
import pandas as pd

# Random Forest
from sklearn.ensemble import RandomForestClassifier
# Dividir dados entre treino e teste
from sklearn.model_selection import train_test_split


def f_treinamento():
    # Importar o dataset e nomear as colunas
    df = pd.read_csv('dataset_final_mod_2.csv')
    
    # Separar X e y
    y = df['rótulo']
    X = df.drop('rótulo', axis=1)

    # Utilizando o mesmo conjunto de dados para os três algoritmos
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=30)

    # Gegar 20 árvores
    n_estimators=20

    # Criar o classificador Random Forest
    floresta = RandomForestClassifier(n_estimators=n_estimators)

    # Treinar o modelo usando os conjuntos de treinamento
    modelo = floresta.fit(X_train,y_train)
    
    return modelo


def f_predicao(modelo, df_predicao):
    # Predizer a resposta para o conjunto de dados de teste
    y_pred = modelo.predict(df_predicao)

    return y_pred
