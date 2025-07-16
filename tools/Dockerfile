FROM golang:1.20-alpine

WORKDIR /app

COPY simulador.go .

RUN go build -o simulador simulador.go

CMD ["./simulador", "-n", "10", "-massivo"]
