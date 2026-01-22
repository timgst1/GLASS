package handlers

import "strings"

func normalizeKey(k string) string {
	k = strings.TrimSpace(k)
	k = strings.TrimPrefix(k, "/")
	return k
}

func normalizePrefix(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "/")
	return p
}
