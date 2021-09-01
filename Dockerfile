FROM golang:1.16-alpine

WORKDIR /go/src/app
COPY . .

RUN go build -v -o geoip-policyd

CMD ["/go/src/app/geoip-policyd", "server"]
