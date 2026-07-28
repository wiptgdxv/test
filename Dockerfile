# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.26.3-alpine3.23
FROM ${GO_IMAGE} AS build

RUN apk add --no-cache ca-certificates
WORKDIR /src

COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" -o /out/client ./cmd/client

FROM scratch AS server

LABEL org.opencontainers.image.title="banner-fingerprint-server" \
      org.opencontainers.image.description="Rule-driven banner fingerprint HTTP service"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/server /server
COPY configs/fingerprints.json /app/configs/fingerprints.json

USER 65532:65532
WORKDIR /app
EXPOSE 8080

ENTRYPOINT ["/server"]
CMD ["serve"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=5 \
  CMD ["/server", "healthcheck", "-url", "http://127.0.0.1:8080/health"]

FROM scratch AS client

LABEL org.opencontainers.image.title="banner-fingerprint-client" \
      org.opencontainers.image.description="Standalone client for the banner fingerprint service"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/client /client

USER 65532:65532
WORKDIR /work

ENTRYPOINT ["/client"]
