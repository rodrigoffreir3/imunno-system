# Arquivo: tools/simulador-malicioso/Dockerfile
FROM golang:1.24-alpine
WORKDIR /app
COPY go.mod ./
RUN go mod tidy
COPY . .
RUN go build -o simulador .
CMD ["./simulador"]