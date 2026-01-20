package authz_test

import (
	"testing"

	"github.com/timgst1/glass/internal/authn"
	"github.com/timgst1/glass/internal/authz"
	"github.com/timgst1/glass/internal/policy"
)

func baseDoc() *policy.Document {
	var s policy.Subject
	s.Name = "team-a"
	s.Match.Kind = "bearer"
	s.Match.Name = "team-a-token"

	r := policy.Role{
		Name: "reader",
		Permissions: []policy.Permission{
			{Action: "read", KeyPrefix: "team-a/"},
			{Action: "read", KeyExact: "shared/foo"},
		},
	}

	return &policy.Document{
		APIVersion: "glass.secretstore/v1alpha1",
		Kind:       "Policy",
		Subjects:   []policy.Subject{s},
		Roles:      []policy.Role{r},
		Bindings: []policy.Binding{
			{Subject: "team-a", Roles: []string{"reader"}},
		},
	}
}

func TestAllowByPrefix(t *testing.T) {
	doc := baseDoc()
	cp, err := authz.Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	sub := authn.Subject{Kind: "bearer", Name: "team-a-token"}
	dec := cp.Evaluate(sub, authz.ActionRead, "team-a/db/password")
	if !dec.Allowed {
		t.Fatalf("expected allowed, got deny: %s", dec.Reason)
	}
}

func TestAllowByExact(t *testing.T) {
	doc := baseDoc()
	cp, _ := authz.Compile(doc)

	sub := authn.Subject{Kind: "bearer", Name: "team-a-token"}
	dec := cp.Evaluate(sub, authz.ActionRead, "shared/foo")
	if !dec.Allowed {
		t.Fatalf("expected allowed, got deny: %s", dec.Reason)
	}
}

func TestDenyWrongSubject(t *testing.T) {
	doc := baseDoc()
	cp, _ := authz.Compile(doc)

	sub := authn.Subject{Kind: "bearer", Name: "someone-else"}
	dec := cp.Evaluate(sub, authz.ActionRead, "team-a/db/password")
	if dec.Allowed {
		t.Fatalf("expected deny, got allow")
	}
}

func TestDenyWrongAction(t *testing.T) {
	doc := baseDoc()
	cp, _ := authz.Compile(doc)

	sub := authn.Subject{Kind: "bearer", Name: "team-a-token"}
	dec := cp.Evaluate(sub, authz.ActionList, "team-a/db/password")
	if dec.Allowed {
		t.Fatalf("expected deny, got allow")
	}
}

func TestCompileDuplicateSubjectMatch(t *testing.T) {
	doc := baseDoc()

	// zweites subject mit gleichem match => ambiguous
	var s2 policy.Subject
	s2.Name = "team-a-2"
	s2.Match.Kind = "bearer"
	s2.Match.Name = "team-a-token"
	doc.Subjects = append(doc.Subjects, s2)

	_, err := authz.Compile(doc)
	if err == nil {
		t.Fatalf("expected compile error for duplicate subject match, got nil")
	}
}
