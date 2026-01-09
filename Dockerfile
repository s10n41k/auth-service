FROM golang:1.25.4-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service ./cmd/main.go

FROM alpine:3.19
WORKDIR /root/
COPY --from=builder /app/auth-service .
EXPOSE 50051
CMD ["./auth-service"]