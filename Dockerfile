FROM golang:1.16-alpine AS builder

WORKDIR /build

# Copy and download dependencies using go.mod
COPY . ./
RUN go mod download

# Set necessarry environment vairables and compile the app
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -v -ldflags="-s -w" -o geoip-policyd .

FROM scratch

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL com.roessner-network-solutions.vendor="Rößner-Network-Solutions"
LABEL version="2021.0.8.1"
LABEL description="Postfix policy service that blocks clients, if they come from too many countires or IP addresses."

# Copy binary to destination image
COPY --from=builder ["/build/geoip-policyd", "/"]

EXPOSE 4646
EXPOSE 8080

ENTRYPOINT ["/geoip-policyd"]
CMD ["server"]