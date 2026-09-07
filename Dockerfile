FROM --platform=$BUILDPLATFORM golang:1.26.8-alpine3.23 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

# Build exclusively from the synchronized vendor tree.
COPY . ./

# Build both executables for the requested image platform.
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}

RUN apk --no-cache --upgrade add git

RUN GIT_TAG=$(git describe --tags --abbrev=0) && echo "tag="${GIT_TAG}"" && \
    GIT_COMMIT=$(git rev-parse --short HEAD) && echo "commit="${GIT_COMMIT}"" && \
    go build -mod vendor -v -ldflags="-s -X main.version=${GIT_TAG}-${GIT_COMMIT}" -o geoip-policyd .

WORKDIR /build/stresstest
RUN go build -mod=vendor -v -ldflags="-s" -o stresstest main.go

FROM alpine:3.23

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL org.opencontainers.image.source="https://github.com/croessner/geoip-policyd"
LABEL org.opencontainers.image.description="Policy server that blocks senders based on country and IP diversity"
LABEL org.opencontainers.image.licenses=AGPL-3
LABEL com.roessner-network-solutions.vendor="Rößner-Network-Solutions"

WORKDIR /usr/app

RUN apk --no-cache --upgrade add ca-certificates bash curl && \
    addgroup -S -g 10001 geoip-policyd && \
    adduser -S -D -H -u 10001 -G geoip-policyd geoip-policyd

# Copy binary to destination image
COPY --from=builder ["/build/geoip-policyd", "./"]
COPY --from=builder ["/build/stresstest/stresstest", "./"]
COPY --from=builder ["/usr/local/go/lib/time/zoneinfo.zip", "/"]

ENV ZONEINFO=/zoneinfo.zip

EXPOSE 4646 8080

USER 10001:10001

ENTRYPOINT ["/usr/app/geoip-policyd"]
CMD ["server"]
