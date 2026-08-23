# Build Stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod first
COPY go.mod ./
COPY backend/ ./backend/
COPY backend/main.go ./frontend/../backend/

# Copy frontend into backend directory so embed relative path resolves cleanly
COPY frontend/ ./backend/frontend/

# Run go mod tidy & build static binary
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o envguard ./backend/main.go

# Final Lightweight Runtime Stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/envguard .

EXPOSE 8080

USER nobody:nobody

ENTRYPOINT ["./envguard"]
