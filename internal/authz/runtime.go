package authz

import (
	"fmt"
	"sync"

	"github.com/timgst1/glass/internal/authn"
	"github.com/timgst1/glass/internal/policy"
)

type PolicySource interface {
	Current() (*policy.Document, bool)
}

// RuntimeAuthorizer compiliert Policy nur neu, wenn sie sich geändert hat
type RuntimeAuthorizer struct {
	src PolicySource

	mu       sync.RWMutex
	lastDoc  *policy.Document
	compiled *CompiledPolicy
}

func NewRuntimeAuthorizer(src PolicySource) *RuntimeAuthorizer {
	return &RuntimeAuthorizer{src: src}
}

func (a *RuntimeAuthorizer) Evaluate(subject authn.Subject, action, key string) Decision {
	doc, ok := a.src.Current()
	if !ok || doc == nil {
		return Deny("no policy available")
	}

	a.mu.RLock()
	if doc == a.lastDoc && a.compiled != nil {
		cp := a.compiled
		a.mu.RUnlock()
		return cp.Evaluate(subject, action, key)
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	//double-check
	if doc != a.lastDoc || a.compiled == nil {
		cp, err := Compile(doc)
		if err != nil {
			return Deny(fmt.Sprintf("Policy compile error :%v", err))
		}
		a.lastDoc = doc
		a.compiled = cp
	}

	return a.compiled.Evaluate(subject, action, key)
}
