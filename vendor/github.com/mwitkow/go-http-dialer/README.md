# HTTP CONNECT tunneling Go Dialer

[![Travis Build](https://travis-ci.org/mwitkow/go-http-dialer.svg)](https://travis-ci.org/mwitkow/go-http-dialer)
[![Go Report Card](https://goreportcard.com/badge/github.com/mwitkow/go-http-dialer)](http://goreportcard.com/report/mwitkow/go-http-dialer)
[![GoDoc](http://img.shields.io/badge/GoDoc-Reference-blue.svg)](https://godoc.org/github.com/mwitkow/go-http-dialer)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A `net.Dialer` drop-in that establishes the TCP connection over an [HTTP CONNECT Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel#HTTP_CONNECT_tunneling).

## Why?!

Some enterprises have fairly restrictive networking environments. They typically operate [HTTP forward proxies](https://en.wikipedia.org/wiki/Proxy_server) that require user authentication. These proxies usually allow  HTTPS (TCP to `:443`) to pass through the proxy using the [`CONNECT`](https://tools.ietf.org/html/rfc2616#section-9.9) method. The `CONNECT` method is basically a HTTP-negotiated "end-to-end" TCP stream... which is exactly what [`net.Conn`](https://golang.org/pkg/net/#Conn) is :)

## But, really, why?

Because if you want to call [gRPC](http://www.grpc.io/) services which are exposed publicly over `:443` TLS over an HTTP proxy, you can't.

Also, this allows you to call any TCP service over HTTP `CONNECT`... if your proxy allows you to `¯\(ツ)/¯`

## Supported features

 - [x] unencrypted connection to proxy (e.g. `http://proxy.example.com:3128`
 - [x] TLS connection to proxy (customizeable) (e.g. `https://proxy.example.com`)
 - [x] customizeable for `Proxy-Authenticate`, with challenge-response semantics
 - [x] out of the box support for `Basic` auth
 - [ ] appropriate `RemoteAddr` remapping
 

## Usage with gRPC



## License

`go-http-dialer` is released under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
