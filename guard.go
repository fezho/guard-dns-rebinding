package guard_dns_rebinding

import (
	"net/http"
	"strings"
)

const (
	localhost = "localhost"
	sourceIP  = "0.0.0.0"
)

type guard struct {
	h             http.Handler
	hostWhitelist map[string]struct{}
	statusCode    int
}

// GuardDNSRebinding is HTTP middleware that guards against DNS rebinding attacks by permitting hosts
// It accecpts a status code (e.g. 403) and a hostNames represents the host whitelist.

// Example:
//
// gdr := GuardDNSRebinding(403, "www.example.com")
//
//
func GuardDNSRebinding(code int, hostNames ...string) func(h http.Handler) http.Handler {
	whitelist := map[string]struct{}{localhost: {}, sourceIP: {}}
	for _, host := range hostNames {
		whitelist[host] = struct{}{}
	}

	fn := func(h http.Handler) http.Handler {
		return guard{h, whitelist, code}
	}

	return fn
}

func (g guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("Host")
	// No host header, invalid request
	if host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Host header might include the port.
	host = strings.Split(host, ":")[0]

	// TODO: use wildmatch?
	if _, ok := g.hostWhitelist[host]; !ok {
		w.WriteHeader(g.statusCode)
		return
	}

	g.h.ServeHTTP(w, r)
}
