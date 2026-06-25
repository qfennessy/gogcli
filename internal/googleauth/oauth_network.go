package googleauth

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var (
	errInvalidListenAddr     = errors.New("invalid listen address; use host or host:port")
	errNonLoopbackManageAddr = errors.New("accounts manager listen address must be loopback")
	errNonLoopbackCallback   = errors.New("OAuth callback listen address must be loopback (127.0.0.1/localhost/[::1]); to front the callback yourself pass --redirect-uri/--redirect-host (e.g. an HTTPS reverse proxy), or use --remote/--manual for headless auth")
)

func normalizeListenAddr(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "127.0.0.1:0", nil
	}

	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw, nil
	}

	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return raw + ":0", nil
	}

	if strings.Count(raw, ":") == 0 {
		return net.JoinHostPort(raw, "0"), nil
	}

	return "", fmt.Errorf("%w: %q", errInvalidListenAddr, raw)
}

func redirectURIFromListener(ln net.Listener) string {
	return listenerBaseURL(ln) + "/oauth2/callback"
}

func resolveServerRedirectURI(ln net.Listener, override string) string {
	if strings.TrimSpace(override) != "" {
		return strings.TrimSpace(override)
	}

	return redirectURIFromListener(ln)
}

func listenerBaseURL(ln net.Listener) string {
	addr := ln.Addr().(*net.TCPAddr)
	return "http://" + net.JoinHostPort(listenerURLHost(addr), strconv.Itoa(addr.Port))
}

func listenerURLHost(addr *net.TCPAddr) string {
	if addr == nil || addr.IP == nil || addr.IP.IsUnspecified() {
		return "127.0.0.1"
	}

	return addr.IP.String()
}

func isLoopbackListenAddr(listenAddr string) (bool, error) {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return false, fmt.Errorf("%w: %q", errInvalidListenAddr, listenAddr)
	}

	if strings.EqualFold(host, "localhost") {
		return true, nil
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback(), nil
}

func validateManagementListenAddr(listenAddr string) error {
	loopback, err := isLoopbackListenAddr(listenAddr)
	if err != nil {
		return err
	}

	if !loopback {
		return fmt.Errorf("%w: %s", errNonLoopbackManageAddr, listenAddr)
	}

	return nil
}

// validateCallbackListenAddr rejects non-loopback binds for the local OAuth
// callback server. It is only meaningful when the redirect URI is derived from
// the listener itself: in that mode the authorization code is delivered to the
// bound socket over plaintext HTTP, so a non-loopback bind would expose the
// code to other hosts on the network.
func validateCallbackListenAddr(listenAddr string) error {
	loopback, err := isLoopbackListenAddr(listenAddr)
	if err != nil {
		return err
	}

	if !loopback {
		return fmt.Errorf("%w: %s", errNonLoopbackCallback, listenAddr)
	}

	return nil
}
