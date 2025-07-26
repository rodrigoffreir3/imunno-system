# Arquivo: tools/simulador-causalidade/Dockerfile (Corrigido)
FROM golang:1.24-alpine
WORKDIR /app
COPY go.mod ./
RUN go mod tidy
COPY . .
# Compila o arquivo v2
RUN go build -o simulador_causalidade_v2 simulador_causalidade_v2.go
# Executa o arquivo v2
CMD ["./simulador_causalidade_v2"]