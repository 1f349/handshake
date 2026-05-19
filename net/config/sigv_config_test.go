// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"crypto/sha256"
	"crypto/sha512"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSigVerifierConfig_Valid(t *testing.T) {
	hprov := sha256.New
	scheme := crypto.RSASig4096Scheme
	t.Run("False", func(t *testing.T) {
		assert.False(t, (&SigVerifierConfig{}).Valid())
		assert.False(t, (&SigVerifierConfig{SigDataHash: hprov}).Valid())
		assert.False(t, (&SigVerifierConfig{Scheme: scheme}).Valid())
		assert.False(t, (&SigVerifierConfig{PublicKeyData: make([]byte, 0)}).Valid())
		assert.False(t, (&SigVerifierConfig{SigDataHash: hprov, Scheme: scheme}).Valid())
		assert.False(t, (&SigVerifierConfig{SigDataHash: hprov, PublicKeyData: make([]byte, 0)}).Valid())
		assert.False(t, (&SigVerifierConfig{Scheme: scheme, PublicKeyData: make([]byte, 0)}).Valid())
	})
	t.Run("True", func(t *testing.T) {
		assert.True(t, (&SigVerifierConfig{SigDataHash: hprov, Scheme: scheme, PublicKeyData: make([]byte, 0)}).Valid())
		_, _, kbts := keySigTest(t, scheme)
		assert.True(t, (&SigVerifierConfig{SigDataHash: hprov, Scheme: scheme, PublicKeyData: kbts}).Valid())
	})
}

func TestSigVerifierConfig_PublicKey(t *testing.T) {
	hprov := sha256.New
	scheme := crypto.RSASig4096Scheme
	k, _, kbts := keySigTest(t, scheme)
	conf := &SigVerifierConfig{SigDataHash: hprov, Scheme: scheme, PublicKeyData: kbts}
	assert.True(t, conf.Valid())
	assert.True(t, k.Equals(conf.PublicKey()))
}

func TestSigVerifierConfig_PublicKeyHash(t *testing.T) {
	hprov := sha256.New
	hprov2 := sha512.New
	scheme := crypto.RSASig4096Scheme
	k, _, kbts := keySigTest(t, scheme)
	conf := &SigVerifierConfig{SigDataHash: hprov2, Scheme: scheme, PublicKeyData: kbts}
	assert.True(t, conf.Valid())
	assert.True(t, k.Equals(conf.PublicKey()))
	assert.Equal(t, crypto.HashBytes(kbts, hprov()), conf.PublicKeyHash(hprov()))
}
