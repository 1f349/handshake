// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func keySigTest(t *testing.T, scheme crypto.SigScheme) (crypto.SigPublicKey, crypto.SigPrivateKey, []byte) {
	k, kp, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, kp)
	assert.NotNil(t, k)
	kbts, err := k.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, kbts)
	return k, kp, kbts
}

func TestSigConfig_KeyHash(t *testing.T) {
	_, kp, kbts := keySigTest(t, crypto.RSASig4096Scheme)
	sigbts, err := kp.Scheme().Sign(kp, kbts)
	assert.NoError(t, err)
	assert.NotNil(t, sigbts)
	sigConf := &SigConfig{Data: sigbts, Key: kbts}
	assert.True(t, sigConf.Valid())
	hsh := crypto.HashBytes(kbts, sha256.New())
	assert.Equal(t, hsh, sigConf.KeyHash(sha256.New()))
}

func TestSigConfig_Valid(t *testing.T) {
	t.Run("False", func(t *testing.T) {
		assert.False(t, (&SigConfig{}).Valid())
		assert.False(t, (&SigConfig{Data: make([]byte, 0)}).Valid())
		assert.False(t, (&SigConfig{Key: make([]byte, 0)}).Valid())
	})
	t.Run("True", func(t *testing.T) {
		assert.True(t, (&SigConfig{Data: make([]byte, 0), Key: make([]byte, 0)}).Valid())
		_, kp, kbts := keySigTest(t, crypto.RSASig4096Scheme)
		sigbts, err := kp.Scheme().Sign(kp, kbts)
		assert.NoError(t, err)
		assert.NotNil(t, sigbts)
		assert.True(t, (&SigConfig{Data: sigbts, Key: kbts}).Valid())
	})
}
