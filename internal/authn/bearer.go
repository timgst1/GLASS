package authn

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"strings"
)

type Bearer struct {
	tokenToSubject map[string]string
}

func NewBearerFromFile(path string) (*Bearer, error) {
	//Unterstützt 2 Formate:
	// 1) Single token: <token>
	// 2) Multi token: <subject> = <token> pro Zeile (oder SUBJECT:token)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(b))
	if raw == "" {
		return nil, errors.New("bearer token file is empty")
	}

	m := parseTokenFile(raw)
	if len(m) == 0 {
		return nil, errors.New("no tokens found in token file")
	}

	return &Bearer{tokenToSubject: m}, nil
}

func (a *Bearer) Authenticate(r *http.Request) (Subject, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return Subject{}, ErrUnauthenticated
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return Subject{}, ErrUnauthenticated
	}

	got := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if got == "" {
		return Subject{}, ErrUnauthenticated
	}

	for tok, subName := range a.tokenToSubject {
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
			return Subject{Kind: "bearer", Name: subName}, nil
		}
	}

	return Subject{}, ErrUnauthenticated
}

// parseTokenFile akzeptiert:
// - "token" (single) -> subject "webhook"
// - "subject=token" je Zeile
// - "subject:token" je Zeile

func parseTokenFile(raw string) map[string]string {
	out := map[string]string{}

	lines := strings.Split(raw, "\n")
	//Single-token shortcut
	if len(lines) == 1 && !strings.Contains(lines[0], "=") && !strings.Contains(lines[0], ":") {
		out[strings.TrimSpace(lines[0])] = "webhook"
		return out
	}

	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}

		var subject, token string
		if strings.Contains(ln, "=") {
			parts := strings.SplitN(ln, "=", 2)
			subject, token = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		} else if strings.Contains(ln, ":") {
			parts := strings.SplitN(ln, ":", 2)
			subject, token = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		} else {
			continue
		}

		if subject == "" || token == "" {
			continue
		}

		out[token] = subject
	}

	return out
}
