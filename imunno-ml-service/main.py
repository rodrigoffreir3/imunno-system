# Arquivo: imunno-ml-service/main.py (Com Feature Engineering Corrigido)

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import logging
import joblib
import pandas as pd # type: ignore

# --- CONFIGURAÇÃO E CARREGAMENTO DO MODELO ---
logging.basicConfig(level=logging.INFO)
app = FastAPI()

# As características EXATAS que foram usadas para treinar o modelo. A ordem importa.
MODEL_FEATURES = [
    'threat_score', 'num_findings', 'is_php', 'cmd_wget', 'cmd_curl', 
    'cmd_nc', 'cmd_netcat', 'cmd_chmod', 'cmd_whoami', 'cmd_uname'
]

try:
    model = joblib.load("imunno_classifier.joblib")
    logging.info("Modelo de classificação de IA 'imunno_classifier.joblib' carregado com sucesso!")
except FileNotFoundError:
    logging.error("Arquivo do modelo 'imunno_classifier.joblib' não encontrado!")
    model = None

# --- DEFINIÇÃO DOS DADOS DE ENTRADA ---
class EventData(BaseModel):
    agent_id: str
    hostname: str
    event_type: str
    details: Dict[str, Any]

# --- ENDPOINTS DA API ---
@app.get("/")
def read_root():
    return {"status": "Imunno ML Service (Classifier) is running", "model_loaded": model is not None}

@app.post("/analyze")
def analyze_event(event: EventData):
    if model is None:
        raise HTTPException(status_code=500, detail="Modelo de IA não está carregado.")

    logging.info(f"Analisando evento do agente {event.agent_id} com o modelo classificador...")

    # 1. PREPARAÇÃO DOS DADOS (Feature Engineering Corrigido)
    # Criamos um dicionário com todas as features esperadas, inicializadas com 0.
    features_dict = {feature: 0 for feature in MODEL_FEATURES}

    if event.event_type == "FILE_EVENT":
        features_dict['threat_score'] = event.details.get("threat_score", 0)
        
        analysis_findings_list = event.details.get("analysis_findings")
        if analysis_findings_list is None:
            analysis_findings_list = []
        features_dict['num_findings'] = len(analysis_findings_list)
        
        file_path = event.details.get("file_path", "")
        features_dict['is_php'] = 1 if file_path.endswith('.php') else 0
    
    elif event.event_type == "PROCESS_EVENT":
        # (Lógica futura para eventos de processo iria aqui)
        # Por enquanto, ele passará um dicionário de zeros, resultando em uma previsão "benigna".
        pass

    # Converte o dicionário para um DataFrame do Pandas com a ordem de colunas correta.
    current_features = pd.DataFrame([features_dict], columns=MODEL_FEATURES)

    # 2. INFERÊNCIA
    prediction_label = model.predict(current_features)[0]
    prediction_text = "malicious" if prediction_label == 1 else "benign"

    logging.info(f"Previsão do modelo: {prediction_text.upper()} (Rótulo: {prediction_label})")

    # 3. RETORNO
    return {
        "prediction": prediction_text,
        "prediction_label": int(prediction_label),
        "threat_score_input": features_dict['threat_score'],
        "message": "Análise de classificação concluída."
    }
