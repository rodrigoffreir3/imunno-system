# Arquivo: imunno-ml-service/train_model.py
# Script completo para treinar o modelo de IA e salvar em imunno_model.joblib

import pandas as pd
from sqlalchemy import create_engine
import warnings
import joblib
from sklearn.ensemble import IsolationForest

def train():
    print("--- INICIANDO PROCESSO DE TREINAMENTO DO MODELO IMUNNO ---")

    warnings.filterwarnings('ignore')
    # CORREÇÃO: Senha ajustada para 'imunno_pass' para corresponder ao docker-compose.yml
    db_url = "postgresql://imunno_user:imunno_pass@postgres:5432/imunno_db"

    try:
        engine = create_engine(db_url)
        print("[PASSO 1/4] Conexão com o banco de dados estabelecida com sucesso.")
    except Exception as e:
        print(f"[ERRO] Falha ao conectar ao banco de dados: {e}")
        return

    print("[PASSO 2/4] Carregando dados do banco...")
    try:
        # CORREÇÃO: Adicionada a coluna 'file_content' para calcular o 'file_size'
        query_files = "SELECT threat_score, file_content, file_path FROM file_events WHERE file_content IS NOT NULL"
        df_files = pd.read_sql_query(query_files, engine)
        print(f"-> Carregados {len(df_files)} eventos de arquivo.")
    except Exception as e:
        print(f"-> Tabela 'file_events' vazia ou com erro: {e}. Criando dataframe vazio.")
        df_files = pd.DataFrame(columns=['threat_score', 'file_content', 'file_path'])

    print("[PASSO 3/4] Criando features para o modelo...")
    if not df_files.empty:
        # CORREÇÃO: Calculando 'file_size' a partir do conteúdo do arquivo
        df_files['file_size'] = df_files['file_content'].str.len()
        df_files['is_php'] = df_files['file_path'].str.endswith('.php').astype(int)
        df_files['is_js'] = df_files['file_path'].str.endswith('.js').astype(int)
        features = df_files[['threat_score', 'file_size', 'is_php', 'is_js']]
        print(f"-> Features criadas com sucesso. Total de amostras: {len(features)}")
    else:
        print("-> Não há dados para criar features.")
        features = pd.DataFrame(columns=['threat_score', 'file_size', 'is_php', 'is_js'])

    print("[PASSO 4/4] Treinando o modelo Isolation Forest...")
    if not features.empty:
        model = IsolationForest(contamination='auto', random_state=42)
        model.fit(features)
        joblib.dump(model, 'imunno_model.joblib')
        print("-> Modelo treinado e salvo com sucesso em 'imunno_model.joblib'.")
    else:
        print("-> Nenhum dado para treinar. Modelo não foi salvo.")

    print("--- PROCESSO DE TREINAMENTO CONCLUÍDO ---")

if __name__ == "__main__":
    train()