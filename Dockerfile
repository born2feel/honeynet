# syntax=docker/dockerfile:1

# 1. Dashboard
FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# 2. Go binary with the dashboard embedded. Pure Go (no cgo), so it runs on distroless/static.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/honeynet ./cmd/honeynet  && mkdir /out/data

# 3. Runtime: no shell, no package manager, non-root. If an attacker ever broke
# out of the emulation there would be nothing here to use.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/honeynet /honeynet
# Pre-create /data owned by nonroot so a fresh named volume inherits writable permissions.
COPY --from=build --chown=65532:65532 /out/data /data
ENV HONEYNET_DATA_DIR=/data \
    HONEYNET_DASHBOARD_ADDR=0.0.0.0:9000
VOLUME /data
EXPOSE 2222 2323 8080 9000
USER nonroot:nonroot
ENTRYPOINT ["/honeynet"]
