# Usar uma imagem base oficial do Python, que seja estável e leve (slim).
# A versão 3.13 é uma escolha excelente e com amplo suporte de bibliotecas.
FROM python:3.13-slim

# Definir o diretório de trabalho padrão dentro do contêiner.
# Todos os comandos a seguir serão executados a partir de /app.
WORKDIR /app

# Copiar o arquivo de dependências PRIMEIRO, de forma isolada.
# Esta é a otimização mais importante. O Docker cria camadas para cada comando.
# Se o arquivo requirements.txt não mudar, o Docker reutilizará a camada
# já pronta com as bibliotecas instaladas, tornando os builds futuros muito mais rápidos.
COPY requirements.txt .

# Instalar as dependências do projeto.
# --no-cache-dir: Não armazena o cache do pip, o que mantém a imagem final menor.
# --upgrade pip: É uma boa prática garantir que estamos usando a versão mais recente do pip.
RUN pip install --no-cache-dir --upgrade pip -r requirements.txt

# Agora que as dependências estão instaladas, copiar o resto dos arquivos da aplicação.
# Isso inclui o main.py e o nosso cérebro de IA, imunno_model.joblib.
COPY . .

# Informar ao Docker que o contêiner escutará na porta 8000 em tempo de execução.
EXPOSE 8000

# O comando que será executado para iniciar a nossa aplicação quando o contêiner for iniciado.
# uvicorn: O servidor ASGI que roda nossa aplicação FastAPI.
# main:app: Diz ao uvicorn para procurar o objeto chamado 'app' dentro do arquivo 'main.py'.
# --host 0.0.0.0: Torna o serviço acessível a partir de fora do contêiner (essencial para o docker-compose).
# --port 8000: A porta que o servidor vai usar.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
