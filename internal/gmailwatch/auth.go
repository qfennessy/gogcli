package gmailwatch

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

type AuthConfig struct {
	VerifyOIDC     bool
	OIDCEmail      string
	OIDCAudience   string
	SharedToken    string
	TrustForwarded bool
}

type OIDCVerifier func(context.Context, string, string, string) (bool, error)

type Authorizer struct {
	Config AuthConfig
	Verify OIDCVerifier
	Warnf  func(string, ...any)
}

func (a *Authorizer) Authorize(request *http.Request) bool {
	if a.Config.VerifyOIDC {
		bearer := BearerToken(request)
		if bearer != "" && a.Verify != nil {
			if ok, err := a.Verify(request.Context(), bearer, Audience(request, a.Config.OIDCAudience, a.Config.TrustForwarded), a.Config.OIDCEmail); ok {
				return true
			} else if err != nil {
				a.warnf("watch: oidc verify failed: %v", err)
			}
		}

		if a.Config.SharedToken != "" {
			return SharedTokenMatches(request, a.Config.SharedToken)
		}

		return false
	}

	if a.Config.SharedToken == "" {
		return true
	}

	return SharedTokenMatches(request, a.Config.SharedToken)
}

// Audience derives the expected OIDC audience for the push endpoint. An explicit
// value (from --oidc-audience) always wins. Otherwise it is built from the
// request, and X-Forwarded-Proto/Host are honored ONLY when trustForwarded is
// set: those headers are attacker-controllable, so trusting them by default
// would let a caller pick the audience their (validly Google-signed) token
// claims, defeating the audience binding.
func Audience(request *http.Request, explicit string, trustForwarded bool) string {
	if explicit != "" {
		return explicit
	}

	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}

	host := request.Host

	if trustForwarded {
		if forwarded := firstForwardedValue(request.Header.Get("X-Forwarded-Proto")); forwarded != "" {
			scheme = forwarded
		}

		if forwarded := firstForwardedValue(request.Header.Get("X-Forwarded-Host")); forwarded != "" {
			host = forwarded
		}
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, request.URL.Path)
}

func BearerToken(request *http.Request) string {
	authorization := request.Header.Get("Authorization")
	if authorization == "" {
		return ""
	}

	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

func SharedTokenMatches(request *http.Request, expected string) bool {
	if expected == "" {
		return false
	}

	token := request.Header.Get("x-gog-token")
	if token == "" {
		token = request.URL.Query().Get("token")
	}

	if token == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func firstForwardedValue(raw string) string {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 {
		return ""
	}

	return strings.TrimSpace(parts[0])
}

func (a *Authorizer) warnf(format string, args ...any) {
	if a.Warnf != nil {
		a.Warnf(format, args...)
	}
}
