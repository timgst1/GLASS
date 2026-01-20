package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/timgst1/glass/internal/policy"
)

func writeTempPolicyFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return p
}

func TestLoadFromFile_ValidPolicy(t *testing.T) {
	yml := `
apiVersion: glass.secretstore/v1alpha1
kind: Policy
metadata:
  name: default
subjects:
  - name: team-a
    match:
      kind: bearer
      name: team-a-token
roles:
  - name: team-a-reader
    permissions:
      - action: read
        keyPrefix: "team-a/"
bindings:
  - subject: team-a
    roles: [team-a-reader]
`

	path := writeTempPolicyFile(t, yml)

	doc, err := policy.LoadFromFile(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if doc.APIVersion == "" || doc.Kind == "" {
		t.Fatalf("expected apiVersion and kind set")
	}
	if len(doc.Subjects) != 1 || len(doc.Roles) != 1 || len(doc.Bindings) != 1 {
		t.Fatalf("unexpected counts: subjects=%d roles=%d bindings=%d", len(doc.Subjects), len(doc.Roles), len(doc.Bindings))
	}
	if doc.Subjects[0].Match.Kind != "bearer" {
		t.Fatalf("expected subject match kind bearer, got %q", doc.Subjects[0].Match.Kind)
	}
}

func TestValidate_UnknownRoleInBinding(t *testing.T) {
	doc := &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects: []policy.Subject{
			{
				Name: "team-a",
				Match: struct {
					Kind string `yaml:"kind"`
					Name string `yaml:"name"`
				}{Kind: "bearer", Name: "team-a-token"},
			},
		},
		Roles: []policy.Role{
			{
				Name: "team-a-reader",
				Permissions: []policy.Permission{
					{Action: "read", KeyPrefix: "team-a/"},
				},
			},
		},
		Bindings: []policy.Binding{
			{Subject: "team-a", Roles: []string{"does-not-exist"}},
		},
	}

	if err := policy.Validate(doc); err == nil {
		t.Fatalf("expected error for unknown role reference, got nil")
	}
}

func TestValidate_KeyPrefixMustEndWithSlash(t *testing.T) {
	doc := &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects: []policy.Subject{
			{
				Name: "team-a",
				Match: struct {
					Kind string `yaml:"kind"`
					Name string `yaml:"name"`
				}{Kind: "bearer", Name: "team-a-token"},
			},
		},
		Roles: []policy.Role{
			{
				Name: "team-a-reader",
				Permissions: []policy.Permission{
					{Action: "read", KeyPrefix: "team-a"},
				},
			},
		},
		Bindings: []policy.Binding{
			{Subject: "team-a", Roles: []string{"team-a-reader"}},
		},
	}

	if err := policy.Validate(doc); err == nil {
		t.Fatalf("expected error for keyPrefix without trailing '/', got nil")
	}
}

func TestValidate_PermissionNeedsPrefixOrExact(t *testing.T) {
	doc := &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects: []policy.Subject{
			{
				Name: "team-a",
				Match: struct {
					Kind string `yaml:"kind"`
					Name string `yaml:"name"`
				}{Kind: "bearer", Name: "team-a-token"},
			},
		},
		Roles: []policy.Role{
			{
				Name: "team-a-reader",
				Permissions: []policy.Permission{
					{Action: "read"},
				},
			},
		},
		Bindings: []policy.Binding{
			{Subject: "team-a", Roles: []string{"team-a-reader"}},
		},
	}

	if err := policy.Validate(doc); err == nil {
		t.Fatalf("expected error for permission without keyPrefix/keyExact, got nil")
	}
}
