package echo

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

// verifySignedCookies returns the cookies whose Express-compatible
// "s:<value>.<sig>" HMAC-SHA256 signature verifies against secret
// (spec §6.1, mendhak-compatible).
func verifySignedCookies(cookies []*http.Cookie, secret string) map[string]string {
	var out map[string]string
	for _, c := range cookies {
		value := c.Value
		// cookie-parser URL-encodes values; "s%3A..." is the common wire form.
		if strings.Contains(value, "%") {
			if decoded, err := url.QueryUnescape(value); err == nil {
				value = decoded
			}
		}
		rest, ok := strings.CutPrefix(value, "s:")
		if !ok {
			continue
		}
		dot := strings.LastIndex(rest, ".")
		if dot <= 0 {
			continue
		}
		payload, sig := rest[:dot], rest[dot+1:]
		if verifyCookieSignature(payload, sig, secret) {
			if out == nil {
				out = make(map[string]string)
			}
			out[c.Name] = payload
		}
	}
	return out
}

// verifyCookieSignature checks the Express cookie-signature scheme:
// base64(HMAC-SHA256(value, secret)) with trailing "=" stripped.
func verifyCookieSignature(payload, sig, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := strings.TrimRight(base64.StdEncoding.EncodeToString(mac.Sum(nil)), "=")
	return subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) == 1
}
