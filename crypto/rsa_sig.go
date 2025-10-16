// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

var RSASig4096Scheme = RSASig4096{}

type RSASig4096 struct {
}

func (r RSASig4096) Name() string {
	return "rsa-sig-4096-sha256"
}

func (r RSASig4096) GenerateKeyPair() (SigPublicKey, SigPrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, rsa4096KeySize*8)
	if err != nil {
		return nil, nil, err
	}
	pka := &RSASig4096PrivateKey{pk}
	return pka.Public(), pka, nil
}

func (r RSASig4096) UnmarshalBinaryPrivateKey(bytes []byte) (SigPrivateKey, error) {
	k, err := RSAPrivateKeyUnmarshalBinary(bytes)
	if err != nil {
		return nil, err
	}
	return &RSASig4096PrivateKey{k}, nil
}

func (r RSASig4096) UnmarshalBinaryPublicKey(bytes []byte) (SigPublicKey, error) {
	k, err := RSAPublicKeyUnmarshalBinary(bytes)
	if err != nil {
		return nil, err
	}
	return &RSASig4096PublicKey{k}, nil
}

func (r RSASig4096) Sign(key SigPrivateKey, msg []byte) ([]byte, error) {
	if key == nil {
		return nil, ErrKeyNil
	}
	if wk, ok := key.(*RSASig4096PrivateKey); ok {
		return rsa.SignPSS(rand.Reader, wk.PrivateKey, crypto.SHA256, HashBytes(msg, sha256.New()), &rsa.PSSOptions{})
	}
	return nil, ErrIncompatibleKey
}

func (r RSASig4096) Verify(key SigPublicKey, msg []byte, sig []byte) (bool, error) {
	if key == nil {
		return false, ErrKeyNil
	}
	if wk, ok := key.(*RSASig4096PublicKey); ok {
		err := rsa.VerifyPSS(wk.PublicKey, crypto.SHA256, HashBytes(msg, sha256.New()), sig, &rsa.PSSOptions{})
		return err == nil, err
	}
	return false, ErrIncompatibleKey
}

func (r RSASig4096) PublicKeySize() int {
	return rsa4096KeySize
}

func (r RSASig4096) PrivateKeySize() int {
	return rsa4096KeySize * 3
}

func (r RSASig4096) SignatureSize() int {
	return rsa4096KeySize
}

// RSASig4096PublicKey wraps *rsa.PublicKey for SigPublicKey
type RSASig4096PublicKey struct {
	*rsa.PublicKey
}

func (k RSASig4096PublicKey) MarshalBinary() (data []byte, err error) {
	return RSAPublicKeyMarshalBinary(k.PublicKey, rsa4096KeySize)
}

func (k RSASig4096PublicKey) Scheme() SigScheme {
	return RSASig4096Scheme
}

func (k RSASig4096PublicKey) Equals(key SigPublicKey) bool {
	if wk, ok := key.(*RSASig4096PublicKey); ok {
		return k.PublicKey.Equal(wk.PublicKey)
	}
	if wk, ok := key.(RSASig4096PublicKey); ok {
		return k.PublicKey.Equal(wk.PublicKey)
	}
	return false
}

// RSASig4096PrivateKey wraps *rsa.PrivateKey for SigPrivateKey
type RSASig4096PrivateKey struct {
	*rsa.PrivateKey
}

func (k RSASig4096PrivateKey) MarshalBinary() (data []byte, err error) {
	return RSAPrivateKeyMarshalBinary(k.PrivateKey, rsa4096KeySize)
}

func (k RSASig4096PrivateKey) Scheme() SigScheme {
	return RSASig4096Scheme
}

func (k RSASig4096PrivateKey) Equals(key SigPrivateKey) bool {
	if wk, ok := key.(*RSASig4096PrivateKey); ok {
		return k.PrivateKey.Equal(wk.PrivateKey)
	}
	if wk, ok := key.(RSASig4096PrivateKey); ok {
		return k.PrivateKey.Equal(wk.PrivateKey)
	}
	return false
}

func (k RSASig4096PrivateKey) Public() SigPublicKey {
	return &RSASig4096PublicKey{&k.PublicKey}
}
