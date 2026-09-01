package modsecurity

import (
	"net"
	"net/http"
	"strings"
)

// appendPeerToXForwardedFor appends the host part of remoteAddr to header's X-Forwarded-For.
// remoteAddr is the incoming peer as host:port. Parse failure leaves the header unchanged.
func appendPeerToXForwardedFor(header http.Header, remoteAddr string) {
	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return
	}
	prior := header.Values("X-Forwarded-For")
	if len(prior) > 0 {
		clientIP = strings.Join(prior, ", ") + ", " + clientIP
	}
	header.Set("X-Forwarded-For", clientIP)
}
