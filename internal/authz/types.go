package authz

import "github.com/timgst1/glass/internal/authn"

const (
	ActionRead  = "read"
	ActionWrite = "write"
	ActionList  = "list"
)

type Decision struct {
	Allowed bool
	Reason  string
}

func Allow(reason string) Decision { return Decision{Allowed: true, Reason: reason} }
func Deny(reason string) Decision  { return Decision{Allowed: false, Reason: reason} }

type Authorizer interface {
	Evaluate(subject authn.Subject, action, key string) Decision
}
