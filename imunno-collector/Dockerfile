# Usa uma imagem base leve e atualizada para Go
FROM golang:1.24-alpine

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia os arquivos de gerenciamento de dependências primeiro para otimizar o cache
COPY go.mod go.sum ./

# Baixa as dependências
RUN go mod download

# Copia todo o código-fonte da aplicação
COPY . .

# Compila a aplicação Go, criando um executável no WORKDIR.
RUN go build -o imunno-collector

# O comando para executar a aplicação quando o container iniciar, usando o caminho absoluto.
CMD ["/app/imunno-collector"]