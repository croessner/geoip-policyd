FROM --platform=$BUILDPLATFORM golang:1.22-alpine3.20 AS builder

WORKDIR /build

# Copy and download dependencies using go.mod
COPY . ./
RUN go mod download

# Set necessarry environment vairables and compile the app
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

RUN apk --no-cache --upgrade add git

RUN GIT_TAG=$(git describe --tags --abbrev=0) && echo "tag="${GIT_TAG}"" && \
    GIT_COMMIT=$(git rev-parse --short HEAD) && echo "commit="${GIT_COMMIT}"" && \
    go build -mod vendor -v -ldflags="-s -X main.version=${GIT_TAG}-${GIT_COMMIT}" -o geoip-policyd .

RUN cd ./stresstest && go build -mod vendor -v -ldflags="-s" -o stresstest main.go

FROM --platform=$BUILDPLATFORM alpine:3.20

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL org.opencontainers.image.source="https://github.com/croessner/geoip-policyd"
LABEL org.opencontainers.image.description="Policy server that blocks senders based on country and IP diversity"
LABEL org.opencontainers.image.licenses=AGPL-3
LABEL com.roessner-network-solutions.vendor="Rößner-Network-Solutions"

WORKDIR /usr/app

RUN apk --no-cache --upgrade add ca-certificates bash curl

# Copy binary to destination image
COPY --from=builder ["/build/geoip-policyd", "./"]
COPY --from=builder ["/build/stresstest/stresstest", "./"]
COPY --from=builder ["/usr/local/go/lib/time/zoneinfo.zip", "/"]

ENV ZONEINFO=/zoneinfo.zip

EXPOSE 4646 8080

ENTRYPOINT ["/usr/app/geoip-policyd"]
CMD ["server"]