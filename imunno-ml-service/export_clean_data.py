
import pandas as pd
from sqlalchemy import create_engine
import logging

# Configuração do logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

def export():
    log.info("--- INICIANDO EXPORTAÇÃO DE DADOS LIMPOS ---")
    db_url = "postgresql://imunno_user:imunno_pass@postgres:5432/imunno_db"
    output_csv_path = "exported_data.csv"

    try:
        engine = create_engine(db_url)
        log.info("[PASSO 1/3] Conexão com o banco de dados estabelecida.")
    except Exception as e:
        log.error(f"[ERRO] Falha ao conectar ao banco de dados: {e}")
        return

    log.info("[PASSO 2/3] Carregando dados da tabela 'file_events'...")
    try:
        query = "SELECT * FROM file_events"
        df = pd.read_sql_query(query, engine)
        log.info(f"-> Carregados {len(df)} eventos de arquivo.")
    except Exception as e:
        log.error(f"[ERRO] Falha ao carregar dados: {e}")
        return

    log.info(f"[PASSO 3/3] Salvando dados em '{output_csv_path}'...")
    if not df.empty:
        df.to_csv(output_csv_path, index=False)
        log.info(f"-> Dados salvos com sucesso. O arquivo '{output_csv_path}' foi criado/substituído.")
    else:
        log.warning("-> Nenhum dado para exportar. O arquivo CSV não foi criado.")

    log.info("--- EXPORTAÇÃO CONCLUÍDA ---")

if __name__ == "__main__":
    export()
