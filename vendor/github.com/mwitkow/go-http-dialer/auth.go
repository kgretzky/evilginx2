// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package http_dialer

import "encoding/base64"

const (
	hdrProxyAuthResp = "Proxy-Authorization"
	hdrProxyAuthReq = "Proxy-Authenticate"
)

// ProxyAuthorization allows for plugging in arbitrary implementations of the "Proxy-Authorization" handler.
type ProxyAuthorization interface {
	// Type represents what kind of Authorization, e.g. "Bearer", "Token", "Digest".
	Type() string

	// Initial allows you to specify an a-priori "Proxy-Authenticate" response header, attached to first request,
	// so you don't need to wait for an additional challenge. If empty string is returned, "Proxy-Authenticate"
	// header is added.
	InitialResponse() string

	// ChallengeResponse returns the content of the "Proxy-Authenticate" response header, that has been chose as
	// response to "Proxy-Authorization" request header challenge.
	ChallengeResponse(challenge string) string
}

type basicAuth struct {
	username string
	password string
}

// AuthBasic returns a ProxyAuthorization that implements "Basic" protocol while ignoring realm challanges.
func AuthBasic(username string, password string) ProxyAuthorization {
	return &basicAuth{username: username, password: password}
}

func (b *basicAuth) Type() string {
	return "Basic"
}

func (b *basicAuth) InitialResponse() string {
	return b.authString()
}

func (b *basicAuth) ChallengeResponse(challenge string) string {
	// challenge can be realm="proxy.com"
	// TODO(mwitkow): Implement realm lookup in AuthBasicWithRealm.
	return b.authString()
}

func (b *basicAuth) authString() string {
	resp := b.username + ":" + b.password
	return base64.StdEncoding.EncodeToString([]byte(resp))
}
