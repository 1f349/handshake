// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRSASig(t *testing.T) {
	scheme := RSASig4096Scheme
	pk, k, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	processTestRSASig(t, k, pk, false)
}

func TestRSASigWrongKey(t *testing.T) {
	scheme := RSASig4096Scheme
	pk, _, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	_, k, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	assert.False(t, k.Public().Equals(pk))
	processTestRSASig(t, k, pk, true)
}

func processTestRSASig(t *testing.T, k SigPrivateKey, pk SigPublicKey, wrongKeys bool) {
	kBts, err := k.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, kBts)
	assert.True(t, len(kBts) == k.Scheme().PrivateKeySize())
	rk, err := k.Scheme().UnmarshalBinaryPrivateKey(kBts)
	assert.NoError(t, err)
	assert.True(t, rk.Equals(k))

	pkBts, err := pk.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, pkBts)
	assert.True(t, len(pkBts) == k.Scheme().PublicKeySize())
	rpk, err := k.Scheme().UnmarshalBinaryPublicKey(pkBts)
	assert.NoError(t, err)
	assert.True(t, rpk.Equals(pk))

	msg := make([]byte, 1024)
	_, _ = rand.Read(msg)

	ctxt, err := k.Scheme().Sign(k, msg)
	assert.NoError(t, err)
	assert.NotNil(t, ctxt)
	assert.True(t, len(ctxt) == pk.Scheme().SignatureSize())
	v, err := pk.Scheme().Verify(pk, msg, ctxt)
	if wrongKeys {
		assert.Error(t, err)
		assert.False(t, v)
	} else {
		assert.NoError(t, err)
		assert.True(t, v)
	}

	v, err = pk.Scheme().Verify(pk, msg, damageBytes(ctxt))
	assert.Error(t, err)
	assert.False(t, v)
	v, err = pk.Scheme().Verify(pk, damageBytes(msg), damageBytes(ctxt))
	assert.Error(t, err)
	assert.False(t, v)
	v, err = pk.Scheme().Verify(pk, damageBytes(msg), ctxt)
	assert.Error(t, err)
	assert.False(t, v)
	v, err = pk.Scheme().Verify(pk, msg, []byte{0, 1, 2, 3, 4, 5, 6})
	assert.Error(t, err)
	assert.False(t, v)
}
