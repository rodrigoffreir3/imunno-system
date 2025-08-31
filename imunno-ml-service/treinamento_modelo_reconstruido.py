#!/usr/bin/env python
# coding: utf-8

# # Treinamento do Modelo de Detecção de Ameaças com Isolation Forest

# In[1]:





# In[2]:


import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns


# ## 1. Carregamento dos Dados

# In[3]:


# Exemplo de carregamento do CSV. Substitua pelo caminho correto se necessário.
df = pd.read_csv("exported_data.csv")  # Arquivo com dados anotados de eventos
df.head()


# In[4]:


# Etapa de Engenharia de Características
# Cria as colunas necessárias para o modelo a partir dos dados existentes.

# 1. Cria a coluna 'file_size' a partir do comprimento do conteúdo do arquivo
df['file_size'] = df['file_content'].astype(str).apply(len)

# 2. Cria a coluna 'is_php' verificando se o caminho termina com .php
df['is_php'] = df['file_path'].str.endswith('.php').astype(int)

# 3. Cria a coluna 'is_js' verificando se o caminho termina com .js
df['is_js'] = df['file_path'].str.endswith('.js').astype(int)

# 4. (Opcional, mas bom para verificação) Mostra as primeiras linhas do dataframe com as novas colunas
print("DataFrame com as novas características:")
df[['file_path', 'file_size', 'is_php', 'is_js']].head()


# ## 2. Pré-processamento

# In[5]:


# Verifica se há valores nulos
print(df.isnull().sum())

# Mostra estatísticas básicas
print(df.describe())

# Converte colunas booleanas se necessário
if df['is_php'].dtype != 'int64':
    df['is_php'] = df['is_php'].astype(int)
if df['is_js'].dtype != 'int64':
    df['is_js'] = df['is_js'].astype(int)

# Visualização opcional
sns.pairplot(df[['threat_score', 'file_size', 'is_php', 'is_js']])
plt.show()


# ## 3. Treinamento com Isolation Forest

# In[6]:


features = ['threat_score', 'file_size', 'is_php', 'is_js']
X = df[features]

# IsolationForest: -1 é anomalia, 1 é normal
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(X)

# Predição (rótulos -1 e 1)
predictions = model.predict(X)
df['predicted'] = predictions


# ## 4. Avaliação (Simples)

# In[7]:


# Supondo que você tenha rótulo real, chamado 'label'
# 1 = normal, -1 = anomalia
if 'label' in df.columns:
    print(confusion_matrix(df['label'], df['predicted']))
    print(classification_report(df['label'], df['predicted']))
else:
    print("Aviso: Coluna 'label' não encontrada. Apenas mostrando a distribuição de predições.")
    print(df['predicted'].value_counts())


# ## 5. Salvamento do Modelo

# In[8]:


joblib.dump(model, "imunno_model.joblib")
print("Modelo salvo como 'imunno_model.joblib'")

