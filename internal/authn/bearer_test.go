package authn_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/timgst1/glass/internal/authn"
)

func writeTempTokenFile(t *testing.T, token string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return p
}

func TestBearer_AuthenticateSuccess(t *testing.T) {
	path := writeTempTokenFile(t, "secret-token\n")
	a, err := authn.NewBearerFromFile(path)
	if err != nil {
		t.Fatalf("NewBearerFromFile: %v", err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example/v1/secret?key=demo", nil)
	r.Header.Set("Authorization", "Bearer secret-token")

	sub, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if sub.Kind != "bearer" {
		t.Fatalf("expected sub.Kind=bearer, got %q", sub.Kind)
	}
}

func TestBearer_AuthenticateMissingHeader(t *testing.T) {
	path := writeTempTokenFile(t, "secret-token")
	a, err := authn.NewBearerFromFile(path)
	if err != nil {
		t.Fatalf("NewBearerFromFile: %v", err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example/v1/secret?key=demo", nil)

	_, err = a.Authenticate(r)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestBearer_AuthenticateWrongToken(t *testing.T) {
	path := writeTempTokenFile(t, "secret-token")
	a, err := authn.NewBearerFromFile(path)
	if err != nil {
		t.Fatalf("NewBearerFromFile: %v", err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example/v1/secret?key=demo", nil)
	r.Header.Set("Authorization", "Bearer wrong-token")

	_, err = a.Authenticate(r)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestBearer_MultiTokenMapsToSubject(t *testing.T) {
	content := "team-a-token=aaa\nteam-b-token=bbb\n"
	path := writeTempTokenFile(t, content)

	a, err := authn.NewBearerFromFile(path)
	if err != nil {
		t.Fatalf("NewBearerFromFile: %v", err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example/v1/secret?key=demo", nil)
	r.Header.Set("Authorization", "Bearer bbb")

	sub, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if sub.Kind != "bearer" || sub.Name != "team-b-token" {
		t.Fatalf("expected bearer/team-b-token, got %q/%q", sub.Kind, sub.Name)
	}
}
