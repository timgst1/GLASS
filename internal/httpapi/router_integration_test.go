package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/timgst1/glass/internal/authn"
	"github.com/timgst1/glass/internal/authz"
	"github.com/timgst1/glass/internal/httpapi"
	"github.com/timgst1/glass/internal/policy"
	"github.com/timgst1/glass/internal/service"
)

type staticPolicySource struct{ doc *policy.Document }

func (s staticPolicySource) Current() (*policy.Document, bool) {
	if s.doc == nil {
		return nil, false
	}
	return s.doc, true
}

func writeTempTokenFile(t *testing.T, token string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return p
}

func docAllowDemo() *policy.Document {
	var s policy.Subject
	s.Name = "eso"
	s.Match.Kind = "bearer"
	s.Match.Name = "webhook"

	r := policy.Role{
		Name: "demo-reader",
		Permissions: []policy.Permission{
			{Action: "read", KeyExact: "demo"},
		},
	}

	return &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects:   []policy.Subject{s},
		Roles:      []policy.Role{r},
		Bindings: []policy.Binding{
			{Subject: "eso", Roles: []string{"demo-reader"}},
		},
	}
}

func docDenyDemo() *policy.Document {
	var s policy.Subject
	s.Name = "eso"
	s.Match.Kind = "bearer"
	s.Match.Name = "webhook"

	r := policy.Role{
		Name: "reader",
		Permissions: []policy.Permission{
			{Action: "read", KeyExact: "something-else"},
		},
	}

	return &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects:   []policy.Subject{s},
		Roles:      []policy.Role{r},
		Bindings: []policy.Binding{
			{Subject: "eso", Roles: []string{"reader"}},
		},
	}
}

func newTestServer(t *testing.T, doc *policy.Document) (*httptest.Server, string) {
	t.Helper()

	tokPath := writeTempTokenFile(t, "secret-token\n")
	bearer, err := authn.NewBearerFromFile(tokPath)
	if err != nil {
		t.Fatalf("NewBearerFromFile: %v", err)
	}

	az := authz.NewRuntimeAuthorizer(staticPolicySource{doc: doc})

	var secretSvc service.SecretService = service.NewMemorySecretService(map[string]string{"demo": "hello"})
	secretSvc = service.NewSecuredSecretService(secretSvc, az)

	h := httpapi.NewRouter(httpapi.Deps{
		SecretService: secretSvc,
		Authenticator: bearer,
	})

	return httptest.NewServer(h), "secret-token"
}

func TestV1Secret_UnauthorizedWithoutHeader(t *testing.T) {
	srv, _ := newTestServer(t, docAllowDemo())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/secret?key=demo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestV1Secret_ForbiddenWhenPolicyDenies(t *testing.T) {
	srv, token := newTestServer(t, docDenyDemo())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secret?key=demo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, resp.StatusCode)
	}
}

func TestV1Secret_OKWhenAllowed(t *testing.T) {
	srv, token := newTestServer(t, docAllowDemo())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secret?key=demo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}

	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["value"] != "hello" {
		t.Fatalf("expected value=hello, got %q", out["value"])
	}
}
