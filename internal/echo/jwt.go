package echo

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// JWT is a decoded (not verified) JSON Web Token.
type JWT struct {
	Header  any `json:"header,omitempty"`
	Payload any `json:"payload,omitempty"`
}

// DecodeJWT decodes the header and payload of a JWT without verifying the
// signature. Both raw tokens and the "Bearer <token>" scheme are accepted.
// Returns nil when the value is not a decodable JWT.
func DecodeJWT(value string) *JWT {
	value = strings.TrimSpace(value)
	if rest, ok := cutPrefixFold(value, "bearer "); ok {
		value = strings.TrimSpace(rest)
	}
	if value == "" {
		return nil
	}

	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return nil
	}
	header := decodeSegment(parts[0])
	payload := decodeSegment(parts[1])
	if header == nil || payload == nil {
		return nil
	}
	return &JWT{Header: header, Payload: payload}
}

func decodeSegment(seg string) any {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return nil
	}
	var out any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}
