package envelope

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Keyring struct {
	activeID string
	keys     map[string][]byte
}

func LoadKeyring(dir, activeID string) (*Keyring, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("kek dir is empty")
	}
	if strings.TrimSpace(activeID) == "" {
		return nil, fmt.Errorf("active kek id is empty")
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	kr := &Keyring{activeID: activeID, keys: map[string][]byte{}}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		id := e.Name()
		p := filepath.Join(dir, id)

		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read kek %q: %w", id, err)
		}
		key, err := parseKEK(b)
		if err != nil {
			return nil, fmt.Errorf("parse kek %q: %w", id, err)
		}
		kr.keys[id] = key
	}

	if len(kr.keys) == 0 {
		return nil, fmt.Errorf("no KEKs found in %q", dir)
	}
	if _, ok := kr.keys[activeID]; !ok {
		return nil, fmt.Errorf("active kek id %q not found in %q", activeID, dir)
	}

	return kr, nil
}

func (k *Keyring) ActiveID() string { return k.activeID }

func (k *Keyring) Get(id string) ([]byte, bool) {
	b, ok := k.keys[id]
	return b, ok
}

func parseKEK(b []byte) ([]byte, error) {
	s := strings.TrimSpace(string(b))

	// Try base64 first
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		if len(dec) != 32 {
			return nil, fmt.Errorf("expected 32 bytes after base64 decode, got %d", len(dec))
		}
		return dec, nil
	}

	// Fallback: teat file as raw bytes
	if len(b) == 32 {
		return b, nil
	}

	return nil, fmt.Errorf("invalid key material: expected 32 raw bytes or base64(32 bytes)")
}
