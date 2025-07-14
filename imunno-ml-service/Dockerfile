# --- Imagem Base Estável e Padrão de Mercado ---
# Usar Python 3.11 sobre Debian (slim). É a escolha mais robusta e compatível
# para o ecossistema de Data Science (Numpy, Scikit-learn, etc).
FROM python:3.11-slim

# --- Ferramentas de Build e Saúde ---
# Usamos 'apt-get' do Debian para instalar as ferramentas.
# 'build-essential' inclui o compilador 'gcc'.
# 'curl' é para o nosso healthcheck.
RUN apt-get update && apt-get install -y build-essential curl --no-install-recommends && rm -rf /var/lib/apt/lists/*

# --- Diretório de Trabalho ---
WORKDIR /app

# --- Instalação de Dependências ---
# Copia e instala as dependências. O pip vai encontrar as versões corretas
# e pré-compiladas (wheels) para este ambiente, evitando a compilação do zero.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Código da Aplicação ---
COPY . .

# --- Execução ---
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
