# Arquivo: imunno-ml-service/train_model.py
# Script completo para treinar o modelo de IA e salvar em imunno_model.joblib

import pandas as pd
import warnings
import joblib
from sklearn.ensemble import IsolationForest
import argparse
import os
import glob

def get_file_features(file_path, threat_score=0):
    """Extrai features de um único arquivo."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        file_size = len(content)
        is_php = 1 if file_path.endswith('.php') else 0
        is_js = 1 if file_path.endswith('.js') else 0
        
        return {
            'threat_score': threat_score,
            'file_size': file_size,
            'is_php': is_php,
            'is_js': is_js,
            'file_path': file_path
        }
    except Exception as e:
        print(f"[AVISO] Não foi possível ler o arquivo {file_path}: {e}")
        return None

def train(malicious_path):
    print("--- INICIANDO PROCESSO DE TREINAMENTO DO MODELO IMUNNO ---")
    warnings.filterwarnings('ignore')
    
    input_csv_path = "imunno-ml-service/exported_data.csv"
    output_model_path = "imunno-ml-service/imunno_model.joblib"
    features_to_use = ['threat_score', 'file_size', 'is_php', 'is_js']

    # PASSO 1: Carregar e processar dados benignos do CSV
    print(f"[PASSO 1/4] Carregando e processando dados benignos do arquivo '{input_csv_path}'...")
    try:
        df_benign = pd.read_csv(input_csv_path)
        print(f"-> Carregados {len(df_benign)} eventos benignos brutos.")

        # Garante que colunas de conteúdo e caminho existam e sejam do tipo correto
        df_benign['file_content'] = df_benign['file_content'].astype(str)
        df_benign['file_path'] = df_benign['file_path'].astype(str)

        # Cria as features a partir das colunas existentes
        df_benign['file_size'] = df_benign['file_content'].str.len()
        df_benign['is_php'] = df_benign['file_path'].str.endswith('.php').astype(int)
        df_benign['is_js'] = df_benign['file_path'].str.endswith('.js').astype(int)
        
        # Agora seleciona apenas as features que o modelo espera
        df_benign = df_benign[features_to_use]
        print(f"-> Features criadas para {len(df_benign)} eventos benignos.")

    except FileNotFoundError:
        print(f"[ERRO] Arquivo '{input_csv_path}' não encontrado. Abortando treinamento.")
        return
    except KeyError as e:
        print(f"[ERRO] Coluna esperada não encontrada no CSV: {e}. Verifique o arquivo '{input_csv_path}'. Abortando.")
        return

    # PASSO 2: Carregar dados maliciosos da pasta fornecida
    print(f"[PASSO 2/4] Carregando dados maliciosos de '{malicious_path}'...")
    malicious_files_data = []
    if malicious_path and os.path.isdir(malicious_path):
        for file_path in glob.glob(os.path.join(malicious_path, '**', '*'), recursive=True):
            if os.path.isfile(file_path):
                features = get_file_features(file_path, threat_score=10)
                if features:
                    malicious_files_data.append(features)
    
    if not malicious_files_data:
        print("-> Nenhum arquivo malicioso encontrado ou o caminho não foi fornecido.")
        df_malicious = pd.DataFrame(columns=features_to_use + ['file_path'])
    else:
        df_malicious = pd.DataFrame(malicious_files_data)
        print(f"-> Carregados {len(df_malicious)} arquivos maliciosos.")

    # PASSO 3: Combinar dados benignos e maliciosos
    print("[PASSO 3/4] Combinando datasets benigno e malicioso...")
    combined_df = pd.concat([df_benign, df_malicious[features_to_use]], ignore_index=True)
    print(f"-> Dataset combinado criado com {len(combined_df)} amostras.")

    # PASSO 4: Treinar o modelo
    print("[PASSO 4/4] Treinando o modelo Isolation Forest...")
    if not combined_df.empty:
        features = combined_df[features_to_use]
        contamination_rate = len(df_malicious) / len(combined_df) if len(combined_df) > 0 else 0.01
        if contamination_rate == 0: contamination_rate = 'auto'

        print(f"-> Taxa de contaminação calculada: {contamination_rate if isinstance(contamination_rate, str) else f'{contamination_rate:.4f}'}")
        model = IsolationForest(contamination=contamination_rate, random_state=42)
        model.fit(features)
        joblib.dump(model, output_model_path)
        print(f"-> Modelo treinado e salvo com sucesso em '{output_model_path}'.")
    else:
        print("-> Nenhum dado para treinar. Modelo não foi salvo.")

    print("--- PROCESSO DE TREINAMENTO CONCLUÍDO ---")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Treina o modelo de detecção de anomalias do Imunno.")
    parser.add_argument('--malicious-path', type=str, required=True, help='Caminho para a pasta contendo arquivos maliciosos para treinamento.')
    args = parser.parse_args()
    
    train(args.malicious_path)