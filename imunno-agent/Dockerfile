# Estágio 1: O Construtor (Builder)
# Usa uma imagem base atualizada do Go
FROM golang:1.24-alpine as builder

# Define o diretório de trabalho
WORKDIR /app

# Instala o 'audit' e suas dependências, necessário para o monitoramento
RUN apk add --no-cache audit

# Copia os arquivos de gerenciamento de dependências
COPY go.mod go.sum ./

# Baixa as dependências
RUN go mod download

# Copia todo o código-fonte da aplicação
COPY . .

# Compila a aplicação Go
RUN go build -o imunno-agent


# Estágio 2: A imagem final começa a partir de uma base Alpine limpa
FROM alpine:latest

# Instala apenas o 'audit', que é a única dependência de runtime
RUN apk add --no-cache audit

# Define o diretório de trabalho
WORKDIR /app

# Copia o script de entrypoint e o executável compilado do estágio 'builder'
COPY --from=builder /app/entrypoint.sh .
COPY --from=builder /app/imunno-agent .

# Garante que o script de entrypoint seja executável
RUN chmod +x ./entrypoint.sh

# Define o entrypoint que iniciará o auditd e depois o agente.
ENTRYPOINT ["/app/entrypoint.sh"]