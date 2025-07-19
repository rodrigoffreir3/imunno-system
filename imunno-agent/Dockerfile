# Usa uma imagem base leve para Go com capacidades de build
FROM golang:1.24-alpine as builder

# Define o diretório de trabalho
WORKDIR /app

# Copia os arquivos de gerenciamento de dependências
COPY go.mod go.sum ./

# Baixa as dependências
RUN go mod download

# Copia todo o código-fonte da aplicação
COPY . .

# Compila a aplicação Go
RUN go build -o imunno-agent


# A imagem final começa a partir de uma base Alpine limpa
FROM alpine:latest

# Define o diretório de trabalho
WORKDIR /app

# Copia o script de entrypoint, o executável e as regras de auditoria
COPY --from=builder /app/entrypoint.sh .
COPY --from=builder /app/imunno-agent .
COPY --from=builder /app/audit.rules .

# Garante que o script de entrypoint seja executável
RUN chmod +x ./entrypoint.sh

# Define o entrypoint que iniciará o agente
ENTRYPOINT ["./entrypoint.sh"]