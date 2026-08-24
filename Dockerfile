# The base image matches the toolchain go.mod requires. With a lower base,
# GOTOOLCHAIN=auto would download a second toolchain during every build —
# a network dependency inside the build, and a non-reproducible result.
FROM golang:1.26-alpine AS builder

ENV GOTOOLCHAIN=local
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s -X github.com/maborak/mabo-tunnel/internal/version.Version=${VERSION}" \
    -o mabo-tunnel-server ./cmd/server

FROM alpine:3.20

RUN adduser -D -u 1000 mabo-tunnel
WORKDIR /app

COPY --from=builder /app/mabo-tunnel-server .

# data/users.txt is deliberately NOT copied. Baking it in would put every user
# token into an image layer, readable by anyone who can pull the image. Provide
# it at runtime with a bind mount (see docker-compose.yml) or a secret.
RUN mkdir -p /app/data && chown mabo-tunnel:mabo-tunnel /app/data

USER mabo-tunnel

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["./mabo-tunnel-server"]
CMD ["--addr=:8080", "--users-file=/app/data/users.txt"]
