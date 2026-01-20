package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadFromFile(path string) (*Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Document
	if err := yaml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	if err := Validate(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

func Validate(d *Document) error {
	if strings.TrimSpace(d.APIVersion) == "" {
		return fmt.Errorf("policy: apiVersion missing")
	}
	if strings.TrimSpace(d.Kind) == "" {
		return fmt.Errorf("policy: kind missing")
	}

	subjectNames := map[string]struct{}{}
	for _, s := range d.Subjects {
		if s.Name == "" || s.Match.Kind == "" || s.Match.Name == "" {
			return fmt.Errorf("policy: subject missing fields")
		}
		if _, ok := subjectNames[s.Name]; ok {
			return fmt.Errorf("policy: duplicate subject name %q", s.Name)
		}
		subjectNames[s.Name] = struct{}{}
	}

	roleNames := map[string]struct{}{}
	for _, r := range d.Roles {
		if r.Name == "" {
			return fmt.Errorf("policy: role name missing")
		}
		if _, ok := roleNames[r.Name]; ok {
			return fmt.Errorf("policy: duplicate role name %q", r.Name)
		}
		roleNames[r.Name] = struct{}{}

		for _, p := range r.Permissions {
			if p.Action == "" {
				return fmt.Errorf("policy: permission action missing in role %q", r.Name)
			}
			if p.KeyPrefix == "" && p.KeyExact == "" {
				return fmt.Errorf("policy: permissions needs keyPrefix or keyExact in role %q", r.Name)
			}
			if p.KeyPrefix != "" && !strings.HasSuffix(p.KeyPrefix, "/") {
				return fmt.Errorf("policy: keyPrefix %q in role %q must end with '/'", p.KeyPrefix, r.Name)
			}
		}
	}

	for _, b := range d.Bindings {
		if _, ok := subjectNames[b.Subject]; !ok {
			return fmt.Errorf("policy: binding references unknown subject %q", b.Subject)
		}
		for _, rn := range b.Roles {
			if _, ok := roleNames[rn]; !ok {
				return fmt.Errorf("policy: binding references unknown role %q", rn)
			}
		}
	}

	return nil
}
