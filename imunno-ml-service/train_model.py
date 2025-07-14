# Arquivo: imunno-ml-service/train_model.py
# Este script é a forma robusta de treinar nosso modelo de IA.
# Ele se conecta ao banco de dados, prepara os dados e treina o modelo,
# salvando o resultado para ser usado pelo serviço principal (main.py).

import pandas as pd
from sqlalchemy import create_engine
import warnings
import joblib
from sklearn.ensemble import IsolationForest

def train():
    """
    Função principal que executa todo o processo de treinamento.
    """
    print("--- INICIANDO PROCESSO DE TREINAMENTO DO MODELO IMUNNO ---")

    # 1. CONEXÃO COM O BANCO DE DADOS
    # ---------------------------------
    warnings.filterwarnings('ignore')
    # Usamos o nome do serviço 'imunno_postgres' como hostname, pois estamos na rede do Docker.
    db_url = "postgresql://imunno_user:imunno_password@imunno_postgres:5432/imunno_db"
    engine = None
    try:
        engine = create_engine(db_url)
        print("[PASSO 1/4] Conexão com o banco de dados estabelecida com sucesso.")
    except Exception as e:
        print(f"[ERRO] Falha ao conectar ao banco de dados: {e}")
        return # Aborta a execução se não conseguir conectar.

    # 2. CARREGAMENTO DOS DADOS
    # -------------------------
    print("[PASSO 2/4] Carregando dados do banco...")
    try:
        query_files = "SELECT threat_score, file_size, file_path FROM file_events"
        df_files = pd.read_sql_query(query_files, engine)
        print(f"-> Carregados {len(df_files)} eventos de arquivo.")
    except Exception:
        print("-> Tabela 'file_events' vazia ou não encontrada. Criando dataframe vazio.")
        df_files = pd.DataFrame(columns=['threat_score', 'file_size', 'file_path'])

    # 3. ENGENHARIA DE FEATURES
    # -------------------------
    print("[PASSO 3/4] Criando features para o modelo...")
    if not df_files.empty:
        df_files['is_php'] = df_files['file_path'].str.endswith('.php').astype(int)
        df_files['is_js'] = df_files['file_path'].str.endswith('.js').astype(int)
        features = df_files[['threat_score', 'file_size', 'is_php', 'is_js']]
        print(f"-> Features criadas com sucesso. Total de amostras: {len(features)}")
    else:
        print("-> Não há dados de arquivo para criar features.")
        features = pd.DataFrame(columns=['threat_score', 'file_size', 'is_php', 'is_js'])

    # 4. TREINAMENTO DO MODELO
    # ------------------------
    print("[PASSO 4/4] Treinando o modelo Isolation Forest...")
    if not features.empty:
        model = IsolationForest(contamination='auto', random_state=42)
        model.fit(features)
        print("-> Modelo treinado com sucesso!")

        model_filename = 'imunno_model.joblib'
        joblib.dump(model, model_filename)
        print(f"-> Modelo salvo com sucesso em: {model_filename}")
    else:
        print("-> Não há dados para treinar. Nenhum modelo foi salvo.")

    print("--- PROCESSO DE TREINAMENTO CONCLUÍDO ---")

if __name__ == "__main__":
    train()
