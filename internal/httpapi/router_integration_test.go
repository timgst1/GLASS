package httpapi_test

import (
	"bytes"
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
	"github.com/timgst1/glass/internal/storage/sqlite"
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

func docAllowDemoReadWrite() *policy.Document {
	var s policy.Subject
	s.Name = "eso"
	s.Match.Kind = "bearer"
	s.Match.Name = "webhook"

	r := policy.Role{
		Name: "demo-rw",
		Permissions: []policy.Permission{
			{Action: "read", KeyExact: "demo"},
			{Action: "write", KeyExact: "demo"},
		},
	}

	return &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects:   []policy.Subject{s},
		Roles:      []policy.Role{r},
		Bindings: []policy.Binding{
			{Subject: "eso", Roles: []string{"demo-rw"}},
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

// List erlaubt für team-a/, read aber nur exakt für team-a/db (Filter-Case!)
func docAllowTeamAListReadDBOnly() *policy.Document {
	var s policy.Subject
	s.Name = "eso"
	s.Match.Kind = "bearer"
	s.Match.Name = "webhook"

	r := policy.Role{
		Name: "team-a-lister",
		Permissions: []policy.Permission{
			{Action: "list", KeyPrefix: "team-a/"},
			{Action: "read", KeyExact: "team-a/db"},
		},
	}

	return &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects:   []policy.Subject{s},
		Roles:      []policy.Role{r},
		Bindings: []policy.Binding{
			{Subject: "eso", Roles: []string{"team-a-lister"}},
		},
	}
}

// Read erlaubt auf team-a/, aber KEIN list -> muss beim /v1/secrets 403 geben
func docAllowTeamAReadNoList() *policy.Document {
	var s policy.Subject
	s.Name = "eso"
	s.Match.Kind = "bearer"
	s.Match.Name = "webhook"

	r := policy.Role{
		Name: "team-a-reader-only",
		Permissions: []policy.Permission{
			{Action: "read", KeyPrefix: "team-a/"},
		},
	}

	return &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects:   []policy.Subject{s},
		Roles:      []policy.Role{r},
		Bindings: []policy.Binding{
			{Subject: "eso", Roles: []string{"team-a-reader-only"}},
		},
	}
}

func newSQLiteService(t *testing.T) service.SecretService {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.sqlite")

	db, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := sqlite.Migrate(db); err != nil {
		t.Fatalf("sqlite.Migrate: %v", err)
	}

	return service.NewSQLiteSecretService(db)
}

func newTestServerWithService(t *testing.T, doc *policy.Document, base service.SecretService) (*httptest.Server, string) {
	t.Helper()

	tokPath := writeTempTokenFile(t, "secret-token\n")
	bearer, err := authn.NewBearerFromFile(tokPath)
	if err != nil {
		t.Fatalf("NewBearerFromFile: %v", err)
	}

	az := authz.NewRuntimeAuthorizer(staticPolicySource{doc: doc})
	secretSvc := service.NewSecuredSecretService(base, az)

	h := httpapi.NewRouter(httpapi.Deps{
		SecretService: secretSvc,
		Authenticator: bearer,
	})

	return httptest.NewServer(h), "secret-token"
}

func newTestServer(t *testing.T, doc *policy.Document) (*httptest.Server, string) {
	t.Helper()
	base := service.NewMemorySecretService(map[string]string{"demo": "hello"})
	return newTestServerWithService(t, doc, base)
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

func TestV1SecretPut_UnauthorizedWithoutHeader(t *testing.T) {
	srv, _ := newTestServerWithService(t, docAllowDemoReadWrite(), newSQLiteService(t))
	defer srv.Close()

	body := bytes.NewBufferString(`{"key":"demo","value":"new"}`)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/secret", body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestV1SecretPut_ForbiddenWhenPolicyDeniesWrite(t *testing.T) {
	srv, token := newTestServerWithService(t, docAllowDemo(), newSQLiteService(t)) // read-only policy
	defer srv.Close()

	body := bytes.NewBufferString(`{"key":"demo","value":"new"}`)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/secret", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, resp.StatusCode)
	}
}

func TestV1SecretPut_OKWhenWriteAllowed_AndGetReturnsNewValue(t *testing.T) {
	srv, token := newTestServerWithService(t, docAllowDemoReadWrite(), newSQLiteService(t))
	defer srv.Close()

	// PUT v1
	body := bytes.NewBufferString(`{"key":"demo","value":"new"}`)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/secret", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do PUT: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}

	var putOut struct {
		Key     string `json:"key"`
		Version int64  `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&putOut); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if putOut.Key != "demo" {
		t.Fatalf("expected key=demo, got %q", putOut.Key)
	}
	if putOut.Version != 1 {
		t.Fatalf("expected version=1, got %d", putOut.Version)
	}

	// GET should return new value
	getReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secret?key=demo", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)

	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("Do GET: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, getResp.StatusCode)
	}

	var out map[string]string
	if err := json.NewDecoder(getResp.Body).Decode(&out); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if out["value"] != "new" {
		t.Fatalf("expected value=new, got %q", out["value"])
	}
}

func TestV1SecretMeta_UnauthorizedWithoutHeader(t *testing.T) {
	srv, _ := newTestServer(t, docAllowDemo())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/secret/meta?key=demo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestV1SecretMeta_ForbiddenWhenPolicyDenies(t *testing.T) {
	srv, token := newTestServer(t, docDenyDemo())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secret/meta?key=demo", nil)
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

func TestV1SecretMeta_OKWhenAllowed(t *testing.T) {
	srv, token := newTestServer(t, docAllowDemo())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secret/meta?key=demo", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}

	var out struct {
		Key       string `json:"key"`
		Version   int64  `json:"version"`
		CreatedAt string `json:"created_at"`
		CreatedBy string `json:"created_by"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if out.Key != "demo" {
		t.Fatalf("expected key=demo, got %q", out.Key)
	}
	if out.Version < 1 {
		t.Fatalf("expected version >= 1, got %d", out.Version)
	}
	if out.CreatedAt == "" {
		t.Fatalf("expected created_at to be set")
	}
	if out.CreatedBy == "" {
		t.Fatalf("expected created_by to be set")
	}
}

func TestV1SecretsList_UnauthorizedWithoutHeader(t *testing.T) {
	seed := map[string]string{
		"team-a/db":  "dbpass",
		"team-a/api": "apipass",
	}
	srv, _ := newTestServerWithService(t, docAllowTeamAListReadDBOnly(), service.NewMemorySecretService(seed))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/secrets?prefix=team-a/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestV1SecretsList_ForbiddenWhenNoListPermission(t *testing.T) {
	seed := map[string]string{
		"team-a/db":  "dbpass",
		"team-a/api": "apipass",
	}
	srv, token := newTestServerWithService(t, docAllowTeamAReadNoList(), service.NewMemorySecretService(seed))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secrets?prefix=team-a/", nil)
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

func TestV1SecretsList_OKAndFiltersUnreadableKeys(t *testing.T) {
	seed := map[string]string{
		"team-a/db":  "dbpass",
		"team-a/api": "apipass",
		"team-b/db":  "other",
	}
	srv, token := newTestServerWithService(t, docAllowTeamAListReadDBOnly(), service.NewMemorySecretService(seed))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secrets?prefix=team-a/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}

	type item struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	var out struct {
		Items []item `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Filter-Case: Policy erlaubt read nur auf team-a/db, nicht team-a/api
	if len(out.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(out.Items))
	}
	if out.Items[0].Key != "team-a/db" {
		t.Fatalf("expected key team-a/db, got %q", out.Items[0].Key)
	}
	if out.Items[0].Value != "dbpass" {
		t.Fatalf("expected value dbpass, got %q", out.Items[0].Value)
	}
}

func TestV1SecretsList_WithMeta_OK(t *testing.T) {
	seed := map[string]string{
		"team-a/db":  "dbpass",
		"team-a/api": "apipass",
	}
	srv, token := newTestServerWithService(t, docAllowTeamAListReadDBOnly(), service.NewMemorySecretService(seed))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secrets?prefix=team-a/&withMeta=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}

	type itemMeta struct {
		Key       string `json:"key"`
		Value     string `json:"value"`
		Version   int64  `json:"version"`
		CreatedAt string `json:"created_at"`
		CreatedBy string `json:"created_by"`
	}
	var out struct {
		Items []itemMeta `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Auch hier Filter-Case -> nur 1 Item (team-a/db)
	if len(out.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(out.Items))
	}
	if out.Items[0].Key != "team-a/db" {
		t.Fatalf("expected key team-a/db, got %q", out.Items[0].Key)
	}
	if out.Items[0].Value != "dbpass" {
		t.Fatalf("expected value dbpass, got %q", out.Items[0].Value)
	}
	if out.Items[0].Version < 1 {
		t.Fatalf("expected version >= 1, got %d", out.Items[0].Version)
	}
	if out.Items[0].CreatedAt == "" {
		t.Fatalf("expected created_at to be set")
	}
	if out.Items[0].CreatedBy == "" {
		t.Fatalf("expected created_by to be set")
	}
}

func TestV1Secret_OKWithLeadingSlashInKey(t *testing.T) {
	srv, token := newTestServer(t, docAllowDemo())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secret?key=/demo", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestV1SecretsList_OKWithLeadingSlashInPrefix(t *testing.T) {
	seed := map[string]string{"team-a/db": "dbpass"}
	srv, token := newTestServerWithService(t, docAllowTeamAListReadDBOnly(), service.NewMemorySecretService(seed))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/secrets?prefix=/team-a/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
}
