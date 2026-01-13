package authn

import (
	"context"
	"errors"
	"net/http"
)

type Subject struct {
	Kind string
	Name string
}

type Authenticator interface {
	Authenticate(r *http.Request) (Subject, error)
}

var ErrUnauthenticated = errors.New("unauthenticated")

type ctxKey int

const subjectKey ctxKey = iota

func WithSubject(ctx context.Context, sub Subject) context.Context {
	return context.WithValue(ctx, subjectKey, sub)
}

func SubjectFromContext(ctx context.Context) (Subject, bool) {
	v := ctx.Value(subjectKey)
	if v == nil {
		return Subject{}, false
	}
	sub, ok := v.(Subject)
	return sub, ok
}
