# syntax=docker/dockerfile:1
# RemoteHound server image: static Go binary on distroless, non-root (SEC-16).
# Base images are pinned by digest; Renovate/Dependabot bumps them.

# The build stage runs on the builder's own platform and cross-compiles, so a multi-arch release
# (linux/amd64 + linux/arm64) needs no emulation: the final stage only copies files.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/jchirayath/remotehound/internal/app.Version=${VERSION} -X github.com/jchirayath/remotehound/internal/app.Commit=${COMMIT}" \
      -o /out/remotehound ./cmd/remotehound \
 && mkdir -p /out/data /out/recordings

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="RemoteHound" \
      org.opencontainers.image.description="Browser-based remote access to Linux, macOS and Windows without a client install" \
      org.opencontainers.image.source="https://github.com/jchirayath/remotehound" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/remotehound /usr/local/bin/remotehound
# Named volumes inherit this ownership on first creation, so the non-root user can write.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/recordings /recordings
USER 65532:65532
EXPOSE 8080 2222
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/remotehound", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/remotehound"]
CMD ["serve"]
