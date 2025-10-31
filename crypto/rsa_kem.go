// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

const rsa4096SharedKeySize = 32
const rsa4096KeySize = 512

var ErrCipherTextSizeWrong = errors.New("cipher text size wrong")

var RSAKem4096Scheme = RSAKem4096{}

type RSAKem4096 struct {
}

func (r RSAKem4096) Name() string {
	return "rsa-kem-4096-sha256"
}

func (r RSAKem4096) GenerateKeyPair() (KemPublicKey, KemPrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, rsa4096KeySize*8)
	if err != nil {
		return nil, nil, err
	}
	pka := &RSAKem4096PrivateKey{pk}
	return pka.Public(), pka, nil
}

func (r RSAKem4096) Encapsulate(key KemPublicKey) (ctxt, secret []byte, err error) {
	if key == nil {
		return nil, nil, ErrKeyNil
	}
	if wk, ok := key.(*RSAKem4096PublicKey); ok {
		secret = make([]byte, rsa4096SharedKeySize)
		_, _ = rand.Read(secret)
		ctxt, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, wk.PublicKey, secret, []byte("kem"))
		return
	}
	return nil, nil, ErrIncompatibleKey
}

func (r RSAKem4096) Decapsulate(key KemPrivateKey, ctxt []byte) (secret []byte, err error) {
	if key == nil {
		return nil, ErrKeyNil
	}
	if len(ctxt) != r.CiphertextSize() {
		return nil, ErrCipherTextSizeWrong
	}
	if wk, ok := key.(*RSAKem4096PrivateKey); ok {
		secret, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, wk.PrivateKey, ctxt, []byte("kem"))
		if err != nil {
			secret = make([]byte, r.SharedKeySize())
			err = nil
			_, err = rand.Read(secret)
		}
		return
	}
	return nil, ErrIncompatibleKey
}

func (r RSAKem4096) UnmarshalBinaryPrivateKey(bytes []byte) (KemPrivateKey, error) {
	k, err := RSAPrivateKeyUnmarshalBinary(bytes)
	if err != nil {
		return nil, err
	}
	return &RSAKem4096PrivateKey{k}, nil
}

func (r RSAKem4096) UnmarshalBinaryPublicKey(bytes []byte) (KemPublicKey, error) {
	k, err := RSAPublicKeyUnmarshalBinary(bytes)
	if err != nil {
		return nil, err
	}
	return &RSAKem4096PublicKey{k}, nil
}

func (r RSAKem4096) CiphertextSize() int {
	return rsa4096KeySize
}

func (r RSAKem4096) SharedKeySize() int {
	return rsa4096SharedKeySize
}

func (r RSAKem4096) PrivateKeySize() int {
	return rsa4096KeySize * 3
}

func (r RSAKem4096) PublicKeySize() int {
	return rsa4096KeySize
}

// RSAKem4096PublicKey wraps *rsa.PublicKey for KemPublicKey
type RSAKem4096PublicKey struct {
	*rsa.PublicKey
}

func (k RSAKem4096PublicKey) MarshalBinary() (data []byte, err error) {
	return RSAPublicKeyMarshalBinary(k.PublicKey, rsa4096KeySize)
}

func (k RSAKem4096PublicKey) Scheme() KemScheme {
	return RSAKem4096Scheme
}

func (k RSAKem4096PublicKey) Equals(key KemPublicKey) bool {
	if wk, ok := key.(*RSAKem4096PublicKey); ok {
		return k.PublicKey.Equal(wk.PublicKey)
	}
	if wk, ok := key.(RSAKem4096PublicKey); ok {
		return k.PublicKey.Equal(wk.PublicKey)
	}
	return false
}

// RSAKem4096PrivateKey wraps *rsa.PrivateKey for KemPrivateKey
type RSAKem4096PrivateKey struct {
	*rsa.PrivateKey
}

func (k RSAKem4096PrivateKey) MarshalBinary() (data []byte, err error) {
	return RSAPrivateKeyMarshalBinary(k.PrivateKey, rsa4096KeySize)
}

func (k RSAKem4096PrivateKey) Scheme() KemScheme {
	return RSAKem4096Scheme
}

func (k RSAKem4096PrivateKey) Equals(key KemPrivateKey) bool {
	if wk, ok := key.(*RSAKem4096PrivateKey); ok {
		return k.PrivateKey.Equal(wk.PrivateKey)
	}
	if wk, ok := key.(RSAKem4096PrivateKey); ok {
		return k.PrivateKey.Equal(wk.PrivateKey)
	}
	return false
}

func (k RSAKem4096PrivateKey) Public() KemPublicKey {
	return &RSAKem4096PublicKey{&k.PublicKey}
}
