package authn

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"strings"
)

type Bearer struct {
	expected string
}

func NewBearerFromFile(path string) (*Bearer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return nil, errors.New("bearer token file is empty")
	}
	return &Bearer{expected: tok}, nil
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

	if subtle.ConstantTimeCompare([]byte(got), []byte(a.expected)) != 1 {
		return Subject{}, ErrUnauthenticated
	}

	return Subject{Kind: "bearer", Name: "webhook"}, nil
}
