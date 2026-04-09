package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_validHeader(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set("Authorization", "ApiKey my-secret-key")

	key, err := GetAPIKey(h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "my-secret-key" {
		t.Errorf("got key %q, want %q", key, "my-secret-key")
	}
}

func TestGetAPIKey_missingAuthorization(t *testing.T) {
	t.Parallel()
	h := http.Header{}

	_, err := GetAPIKey(h)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("got error %v, want %v", err, ErrNoAuthHeaderIncluded)
	}
}

func TestGetAPIKey_malformedAuthorization(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set("Authorization", "Bearer not-an-api-key")

	_, err := GetAPIKey(h)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("got error %v, want malformed authorization header", err)
	}
}
