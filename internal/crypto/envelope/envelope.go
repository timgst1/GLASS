package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type Envelope struct {
	kr *Keyring
}

func New(kr *Keyring) *Envelope {
	return &Envelope{kr: kr}
}

// Stored in DB:
// - value = base64(ciphertext)
// - value_nonce = base64(nonce)
// - wrapped_dek = base64(wrapped DEK)
// - wrap_nonce = base64(nonce used to wrap DEK)
// - kek_id = which KEK was used
type EncryptedValue struct {
	Enc        int
	KekID      string
	Ciphertext string
	Nonce      string
	WrappedDEK string
	WrapNonce  string
}

func (e *Envelope) Encrypt(key string, version int64, plaintext []byte) (EncryptedValue, error) {
	if e == nil || e.kr == nil {
		return EncryptedValue{}, fmt.Errorf("envelope is nil")
	}

	// DEK per secret version
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return EncryptedValue{}, err
	}

	kekID := e.kr.ActiveID()
	kek, ok := e.kr.Get(kekID)
	if !ok {
		return EncryptedValue{}, fmt.Errorf("active kek %q not found", kekID)
	}

	// Encrypt secret value with DEK
	ct, nonce, err := gcmEncrypt(dek, aad(key, version, "val"), plaintext)
	if err != nil {
		return EncryptedValue{}, err
	}

	// Wrap DEK with KEK
	wrapped, wrapNonce, err := gcmEncrypt(kek, aad(key, version, "dek"), dek)
	if err != nil {
		return EncryptedValue{}, err
	}

	return EncryptedValue{
		Enc:        1,
		KekID:      kekID,
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
		WrapNonce:  base64.StdEncoding.EncodeToString(wrapNonce),
	}, nil
}

func (e *Envelope) Decrypt(key string, version int64, ev EncryptedValue) ([]byte, error) {
	if e == nil || e.kr == nil {
		return nil, fmt.Errorf("envelope is nil")
	}

	kek, ok := e.kr.Get(ev.KekID)
	if !ok {
		return nil, fmt.Errorf("unknown kek_id %q", ev.KekID)
	}

	wrapped, err := base64.StdEncoding.DecodeString(ev.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped_dek: %w", err)
	}
	wrapNonce, err := base64.StdEncoding.DecodeString(ev.WrapNonce)
	if err != nil {
		return nil, fmt.Errorf("decode wrap_nonce: %w", err)
	}

	dek, err := gcmDecrypt(kek, aad(key, version, "dek"), wrapNonce, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid dek length %d", len(dek))
	}

	ct, err := base64.StdEncoding.DecodeString(ev.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(ev.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	pt, err := gcmDecrypt(dek, aad(key, version, "val"), nonce, ct)
	if err != nil {
		return nil, fmt.Errorf("decrypt value: %w", err)
	}
	return pt, nil
}

func (e *Envelope) RewrapDEK(key string, version int64, ev EncryptedValue, newKekID string) (EncryptedValue, error) {
	if e == nil || e.kr == nil {
		return EncryptedValue{}, fmt.Errorf("envelope is nil")
	}
	if ev.Enc != 1 {
		return EncryptedValue{}, fmt.Errorf("cannot rewrap: enc=%d (expected 1)", ev.Enc)
	}
	if ev.KekID == "" {
		return EncryptedValue{}, fmt.Errorf("cannot rewrap: empty kek_id")
	}
	if newKekID == "" {
		return EncryptedValue{}, fmt.Errorf("cannot rewrap: empty new kek_id")
	}
	if ev.KekID == newKekID {
		return ev, nil
	}

	oldKEK, ok := e.kr.Get(ev.KekID)
	if !ok {
		return EncryptedValue{}, fmt.Errorf("unkown kek_id %q", ev.KekID)
	}
	newKEK, ok := e.kr.Get(newKekID)
	if !ok {
		return EncryptedValue{}, fmt.Errorf("unknown new kek_id %q", newKekID)
	}

	wrapped, err := base64.StdEncoding.DecodeString(ev.WrappedDEK)
	if err != nil {
		return EncryptedValue{}, fmt.Errorf("decode wrapped_dek: %w", err)
	}
	wrapNonce, err := base64.StdEncoding.DecodeString(ev.WrapNonce)
	if err != nil {
		return EncryptedValue{}, fmt.Errorf("decode wrap_nonce: %w", err)
	}

	//Unwrap with old KEK
	dek, err := gcmDecrypt(oldKEK, aad(key, version, "dek"), wrapNonce, wrapped)
	if err != nil {
		return EncryptedValue{}, fmt.Errorf("unwrap dek: %w", err)
	}
	if len(dek) != 32 {
		return EncryptedValue{}, fmt.Errorf("invalid dek length %d", len(dek))
	}

	//Wrap with new KEK
	newWrapped, newWrapNonce, err := gcmEncrypt(newKEK, aad(key, version, "dek"), dek)
	if err != nil {
		return EncryptedValue{}, fmt.Errorf("wrap dek: %w", err)
	}

	ev.KekID = newKekID
	ev.WrappedDEK = base64.StdEncoding.EncodeToString(newWrapped)
	ev.WrapNonce = base64.StdEncoding.EncodeToString(newWrapNonce)
	return ev, nil
}

func aad(key string, version int64, purpose string) []byte {
	// binds ciphertext to key+version to prevent swapping between records
	return []byte(fmt.Sprintf("glass:v1:%s:%d:%s", key, version, purpose))
}

func gcmEncrypt(key []byte, aad []byte, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

func gcmDecrypt(key []byte, aad []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size %d", len(nonce))
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}
