# Arquivo: tools/simulador-bem/Dockerfile
FROM golang:1.24-alpine
WORKDIR /app
COPY go.mod ./
RUN go mod tidy
COPY . .
RUN go build -o simulador_bem .
CMD ["./simulador_bem"]