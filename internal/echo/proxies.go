package echo

import (
	"net"
	"net/netip"
	"strings"
)

// defaultTrusted are the always-trusted ranges (spec §6.2): loopback,
// link-local, and RFC1918.
var defaultTrusted = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
}

// ProxyChecker resolves the client IP through trusted proxies.
type ProxyChecker struct {
	trusted []netip.Prefix
}

// NewProxyChecker returns a checker trusting the default ranges plus extra.
func NewProxyChecker(extra []netip.Prefix) *ProxyChecker {
	trusted := make([]netip.Prefix, 0, len(defaultTrusted)+len(extra))
	trusted = append(trusted, defaultTrusted...)
	trusted = append(trusted, extra...)
	return &ProxyChecker{trusted: trusted}
}

// Trusted reports whether addr belongs to a trusted range.
func (p *ProxyChecker) Trusted(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range p.trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// PeerIP extracts the IP from a socket remote address ("host:port").
func PeerIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// Resolve returns the client IP and, when the request came through trusted
// proxies, the full X-Forwarded-For chain (spec §6.2): the IP is the first
// untrusted address walking the chain right-to-left; if every entry is
// trusted, the leftmost entry is used.
func (p *ProxyChecker) Resolve(remoteAddr string, xff []string) (string, []string) {
	peer := PeerIP(remoteAddr)

	var chain []string
	for _, value := range xff {
		for _, entry := range strings.Split(value, ",") {
			if entry = strings.TrimSpace(entry); entry != "" {
				chain = append(chain, entry)
			}
		}
	}

	if len(chain) == 0 || !p.Trusted(peer) {
		return peer, nil
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if !p.Trusted(chain[i]) {
			return chain[i], chain
		}
	}
	return chain[0], chain
}
