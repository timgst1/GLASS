package authz

import (
	"errors"
	"fmt"
	"strings"

	"github.com/timgst1/glass/internal/authn"
	"github.com/timgst1/glass/internal/policy"
)

type CompiledPolicy struct {
	//matchKey(kind:name) -> subjectAlias (Subject.Name aus YAML)
	subjectAliasByMatch map[string]string

	//subjectAlias -> roleNames
	rolesBySubject map[string][]string

	//roleName -> permissions
	permsByRole map[string][]permission
}

type permission struct {
	Action    string
	KeyPrefix string
	KeyExact  string
}

func Compile(doc *policy.Document) (*CompiledPolicy, error) {
	if doc == nil {
		return nil, errors.New("policy document is nil")
	}

	cp := &CompiledPolicy{
		subjectAliasByMatch: map[string]string{},
		rolesBySubject:      map[string][]string{},
		permsByRole:         map[string][]permission{},
	}

	for _, s := range doc.Subjects {
		mk := matchKey(strings.TrimSpace(s.Match.Kind), strings.TrimSpace(s.Match.Name))
		if mk == ":" {
			return nil, fmt.Errorf("policy: subject match kind/name missing for subject %q", s.Name)
		}
		if _, exists := cp.subjectAliasByMatch[mk]; exists {
			return nil, fmt.Errorf("policy: duplicate subject match %q", mk)
		}
		cp.subjectAliasByMatch[mk] = s.Name
	}

	for _, r := range doc.Roles {
		var perms []permission
		for _, p := range r.Permissions {
			perms = append(perms, permission{
				Action:    strings.ToLower(strings.TrimSpace(p.Action)),
				KeyPrefix: p.KeyPrefix,
				KeyExact:  p.KeyExact,
			})
		}
		cp.permsByRole[r.Name] = perms
	}

	for _, b := range doc.Bindings {
		cp.rolesBySubject[b.Subject] = append(cp.rolesBySubject[b.Subject], b.Roles...)
	}

	return cp, nil
}

func (cp *CompiledPolicy) Evaluate(subject authn.Subject, action, key string) Decision {
	if cp == nil {
		return Deny("no policy loaded")
	}

	action = strings.ToLower(strings.TrimSpace(action))
	key = normalizeKey(key)
	if key == "" {
		return Deny("empty key")
	}

	alias, ok := cp.subjectAliasByMatch[matchKey(subject.Kind, subject.Name)]
	if !ok {
		return Deny("unknown subject")
	}

	roleNames := cp.rolesBySubject[alias]
	for _, rn := range roleNames {
		perms := cp.permsByRole[rn]
		for _, p := range perms {
			if p.Action != action {
				continue
			}
			if p.KeyExact != "" && key == p.KeyExact {
				return Allow(fmt.Sprintf("role=%s exact=%s", rn, p.KeyExact))
			}
			if p.KeyPrefix != "" && strings.HasPrefix(key, p.KeyPrefix) {
				return Allow(fmt.Sprintf("role=%s prefix=%s", rn, p.KeyPrefix))
			}
		}
	}

	return Deny("no matching permission")
}

func matchKey(kind, name string) string {
	return strings.TrimSpace(kind) + ":" + strings.TrimSpace(name)
}

func normalizeKey(k string) string {
	k = strings.TrimSpace(k)
	k = strings.TrimPrefix(k, "/")
	return k
}
