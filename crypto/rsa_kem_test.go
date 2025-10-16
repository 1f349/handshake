// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"crypto/subtle"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRSAKem(t *testing.T) {
	scheme := RSAKem4096Scheme
	pk, k, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	processTestRSAKem(t, k, pk, false)
}

func TestRSAKemWrongKey(t *testing.T) {
	scheme := RSAKem4096Scheme
	pk, _, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	_, k, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	assert.False(t, k.Public().Equals(pk))
	processTestRSAKem(t, k, pk, true)
}

func processTestRSAKem(t *testing.T, k KemPrivateKey, pk KemPublicKey, wrongKeys bool) {
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

	ctxt, secret, err := pk.Scheme().Encapsulate(pk)
	assert.NoError(t, err)
	assert.NotNil(t, secret)
	assert.NotNil(t, ctxt)
	assert.True(t, len(ctxt) == pk.Scheme().CiphertextSize())
	assert.True(t, len(secret) == pk.Scheme().SharedKeySize())
	rSecret, err := k.Scheme().Decapsulate(k, ctxt)
	if wrongKeys {
		assert.Error(t, err)
		assert.Nil(t, rSecret)
	} else {
		assert.NoError(t, err)
		assert.NotNil(t, rSecret)
		assert.True(t, len(rSecret) == k.Scheme().SharedKeySize())
		assert.True(t, subtle.ConstantTimeCompare(secret, rSecret) == 1)
	}

	rSecret, err = k.Scheme().Decapsulate(k, damageBytes(ctxt))
	assert.Error(t, err)
	assert.Nil(t, rSecret)
	rSecret, err = k.Scheme().Decapsulate(k, []byte{0, 1, 2, 3, 4, 5, 6})
	assert.Error(t, err)
	assert.Nil(t, rSecret)
}
