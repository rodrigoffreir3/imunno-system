# Usa uma imagem base leve para Python
FROM python:3.11-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia o arquivo de requisitos para o diretório de trabalho
COPY requirements.txt .

# --- CORREÇÃO APLICADA AQUI ---
# Instala as dependências Python listadas no requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo o restante do código da aplicação para o diretório de trabalho
COPY . .

# Expõe a porta que a aplicação FastAPI/Uvicorn usará
EXPOSE 5000

# Comando para iniciar o servidor Uvicorn quando o container iniciar
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]