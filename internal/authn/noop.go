package authn

import "net/http"

type Noop struct{}

func (Noop) Authenticate(r *http.Request) (Subject, error) {
	return Subject{Kind: "none", Name: "anonymous"}, nil
}
