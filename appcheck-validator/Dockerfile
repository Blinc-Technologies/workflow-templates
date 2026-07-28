# --- build stage ---
# Built with --platform=$BUILDPLATFORM so this stage always runs natively
# (no QEMU emulation needed); Go's own cross-compiler produces the
# TARGETARCH binary via the GOOS/GOARCH env vars below.
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /appcheck-validator .

# --- final stage ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /appcheck-validator /appcheck-validator

USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/appcheck-validator"]
