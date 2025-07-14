# --- Imagem Base Estável ---
# Usar Python 3.11, uma versão moderna, rápida e com suporte de longo prazo (LTS).
# É a escolha perfeita para produção, garantindo compatibilidade com todas as bibliotecas.
FROM python:3.11-slim

# --- Ferramentas de Build ---
# Instala o compilador 'gcc' e outras ferramentas essenciais ANTES de qualquer outra coisa.
# Isso prepara o ambiente para compilar pacotes como o scikit-learn.
RUN apt-get update && apt-get install -y build-essential --no-install-recommends && rm -rf /var/lib/apt/lists/*

# --- Diretório de Trabalho ---
WORKDIR /app

# --- Instalação de Dependências ---
# Copia e instala as dependências de um arquivo requirements.txt limpo.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Código da Aplicação ---
# Copia o resto da aplicação para o contêiner.
COPY . .

# --- Execução ---
# Expõe a porta e define o comando para iniciar o servidor.
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
