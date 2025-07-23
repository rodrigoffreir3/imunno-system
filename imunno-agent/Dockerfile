# Estágio 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache audit

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compila o agente de forma estática
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o imunno-agent .

# ---

# Estágio 2: Final
FROM alpine:latest

# Instala apenas o 'audit', que é a única dependência de runtime
RUN apk add --no-cache audit

WORKDIR /app

# Copia o script de entrypoint e APENAS o executável compilado do 'builder'
COPY --from=builder /app/entrypoint.sh .
COPY --from=builder /app/imunno-agent .

# Garante que o script seja executável
RUN chmod +x ./entrypoint.sh

# Define o entrypoint
ENTRYPOINT ["./entrypoint.sh"]