package guard_dns_rebinding

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGuardDNSRebinding_NotAllow(t *testing.T) {
	r := newRequest("GET", "http://www.example.com/", "www.example.com")
	w := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	GuardDNSRebinding(http.StatusForbidden)(testHandler).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad status: got %v want %v", w.Code, http.StatusForbidden)
	}
}

func TestGuardDNSRebinding_Allow(t *testing.T) {
	r := newRequest("GET", "http://www.example.com/", "www.example.com")
	w := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	GuardDNSRebinding(http.StatusForbidden, "www.example.com")(testHandler).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("bad status: got %v want %v", w.Code, http.StatusOK)
	}
}

func TestGuardDNSRebinding_BadRequest(t *testing.T) {
	r := newRequest("GET", "http://www.example.com/", "")
	w := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	GuardDNSRebinding(http.StatusForbidden, "www.example.com")(testHandler).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad status: got %v want %v", w.Code, http.StatusBadRequest)
	}
}

func newRequest(method, url string, host string) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if host != "" {
		req.Header.Set("Host", host)
	}
	if err != nil {
		panic(err)
	}
	return req
}
