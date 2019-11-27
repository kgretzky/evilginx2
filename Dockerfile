FROM golang:1.13.1-alpine as build

RUN apk add --update \
    git \
  && rm -rf /var/cache/apk/*

RUN wget -O /usr/local/bin/dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64 && chmod +x /usr/local/bin/dep

WORKDIR /go/src/github.com/kgretzky/evilginx2

COPY go.mod go.sum ./

ENV GO111MODULE on

RUN go mod download

COPY . /go/src/github.com/kgretzky/evilginx2

RUN go build -o ./bin/evilginx main.go

FROM alpine:3.8

RUN apk add --update \
    ca-certificates \
  && rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=build /go/src/github.com/kgretzky/evilginx2/bin/evilginx /app/evilginx
COPY ./phishlets/*.yaml /app/phishlets/

VOLUME ["/app/phishlets/"]

EXPOSE 443 80 53/udp

ENTRYPOINT ["/app/evilginx"]
