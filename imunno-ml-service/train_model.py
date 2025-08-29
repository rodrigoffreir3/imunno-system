# Arquivo: imunno-ml-service/train_model.py
# Script completo para treinar o modelo de IA e salvar em imunno_model.joblib

import pandas as pd
from sqlalchemy import create_engine
import warnings
import joblib
from sklearn.ensemble import IsolationForest

def train():
    print("--- INICIANDO PROCESSO DE TREINAMENTO DO MODELO IMUNNO (A PARTIR DE CSV) ---")
    warnings.filterwarnings('ignore')
    input_csv_path = "exported_data.csv"

    print(f"[PASSO 1/3] Carregando dados do arquivo '{input_csv_path}'...")
    try:
        df = pd.read_csv(input_csv_path)
        print(f"-> Carregados {len(df)} eventos de arquivo.")
    except FileNotFoundError:
        print(f"[ERRO] Arquivo '{input_csv_path}' não encontrado. Abortando treinamento.")
        return

    print("[PASSO 2/3] Criando features para o modelo...")
    if not df.empty:
        # Garante que a coluna 'file_content' seja tratada como string para evitar erros
        df['file_content'] = df['file_content'].astype(str)
        
        df['file_size'] = df['file_content'].str.len()
        df['is_php'] = df['file_path'].str.endswith('.php').astype(int)
        df['is_js'] = df['file_path'].str.endswith('.js').astype(int)
        
        # Seleciona apenas as features que o modelo espera
        features_to_use = ['threat_score', 'file_size', 'is_php', 'is_js']
        features = df[features_to_use]
        print(f"-> Features criadas com sucesso. Total de amostras: {len(features)}")
    else:
        print("-> Não há dados para criar features.")
        features = pd.DataFrame(columns=features_to_use)

    print("[PASSO 3/3] Treinando o modelo Isolation Forest...")
    if not features.empty:
        # Usando o contamination que ajustamos anteriormente
        model = IsolationForest(contamination=0.01, random_state=42)
        model.fit(features)
        joblib.dump(model, 'imunno_model.joblib')
        print("-> Modelo treinado e salvo com sucesso em 'imunno_model.joblib'.")
    else:
        print("-> Nenhum dado para treinar. Modelo não foi salvo.")

    print("--- PROCESSO DE TREINAMENTO CONCLUÍDO ---")

if __name__ == "__main__":
    train()