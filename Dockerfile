FROM node:24-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# vite writes to ../internal/webui/dist
RUN mkdir -p ../internal/webui/dist && npm run build

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/secure-exchange ./cmd/secure-exchange \
 && mkdir -p /out/data/staging /out/data/blobs

# Preview worker: renders untrusted files with LibreOffice/poppler/ffmpeg. Build with
# --target worker; the last stage (the app) stays the default.
FROM debian:bookworm-slim AS worker
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils ffmpeg fonts-noto-cjk fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*
# /data too: whichever container first mounts the empty sxdata volume seeds its ownership.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build /out/secure-exchange /secure-exchange
USER 65532:65532
# exec form: the worker is PID 1 and makes itself non-dumpable; don't add an init (init: true), which would hold the env readable.
ENTRYPOINT ["/secure-exchange", "worker"]

# worker + Go toolchain for the //go:build tools tests (source mounted at /src).
FROM worker AS worker-test
USER root
COPY --from=golang:1.27-bookworm /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH CGO_ENABLED=0
WORKDIR /src
ENTRYPOINT []
CMD ["go", "test", "-tags", "tools", "-count=1", "-covermode=atomic", "-coverprofile=coverage-tools.out", "./internal/preview/...", "./internal/httpapi/..."]

# The app (default, last stage). ffmpeg burns watermarks into video segments per request;
# DejaVu is the watermark font (SX_FONT_FILE).
FROM debian:bookworm-slim AS app
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates ffmpeg fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*
# 65532 = nonroot; the sxdata volume inherits this ownership.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build /out/secure-exchange /secure-exchange
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/secure-exchange"]
