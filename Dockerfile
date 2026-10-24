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

FROM gcr.io/distroless/static-debian12:nonroot
# 65532 = distroless nonroot; the sxdata volume inherits this ownership.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build /out/secure-exchange /secure-exchange
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/secure-exchange"]
