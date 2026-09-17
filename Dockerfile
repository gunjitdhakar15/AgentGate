# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/agentgate ./cmd/agentgate
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/eval-harness ./cmd/eval-harness
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/mock-tools ./cmd/mock-tools

# Production stage
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /bin/agentgate /usr/local/bin/agentgate
COPY --from=builder /bin/eval-harness /usr/local/bin/eval-harness
COPY --from=builder /bin/mock-tools /usr/local/bin/mock-tools
COPY --from=builder /app/configs /app/configs
COPY --from=builder /app/eval /app/eval

EXPOSE 8700

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/agentgate"]
CMD ["-serve", ":8700", "-demo"]
