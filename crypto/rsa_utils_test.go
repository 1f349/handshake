// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

const rsaKeySizeTesting = 2048

func TestRSAKeyBinaryMarshalUnmarshal(t *testing.T) {
	ok, err := rsa.GenerateKey(rand.Reader, rsaKeySizeTesting)
	assert.NoError(t, err)
	assert.NotNil(t, ok)
	assert.NoError(t, ok.Validate())
	pkBts, err := RSAPrivateKeyMarshalBinary(ok, rsaKeySizeTesting/8)
	assert.NoError(t, err)
	assert.NotNil(t, pkBts)
	kBts, err := RSAPublicKeyMarshalBinary(&ok.PublicKey, rsaKeySizeTesting/8)
	assert.NoError(t, err)
	assert.NotNil(t, kBts)
	pk, err := RSAPrivateKeyUnmarshalBinary(pkBts)
	assert.NoError(t, err)
	assert.NotNil(t, pk)
	assert.True(t, pk.Equal(ok))
	k, err := RSAPublicKeyUnmarshalBinary(kBts)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	assert.True(t, k.Equal(&ok.PublicKey))
}

func TestRSAKeyBinaryMarshalUnmarshalFails(t *testing.T) {
	ok, err := rsa.GenerateKey(rand.Reader, rsaKeySizeTesting)
	ok.Primes = nil
	assert.NoError(t, err)
	assert.NotNil(t, ok)
	assert.Error(t, ok.Validate())
	pkBts, err := RSAPrivateKeyMarshalBinary(ok, rsaKeySizeTesting/8)
	assert.Error(t, err)
	assert.Equal(t, Err2PrimesRequired, err)
	assert.Nil(t, pkBts)
	ok.Primes = []*big.Int{nil, nil, nil}
	pkBts, err = RSAPrivateKeyMarshalBinary(ok, rsaKeySizeTesting/8)
	assert.Error(t, err)
	assert.Equal(t, Err2PrimesRequired, err)
	pk, err := RSAPrivateKeyUnmarshalBinary(make([]byte, RSA_MIN_KEY_SIZE*3+1))
	assert.Error(t, err)
	assert.Nil(t, pk)
	assert.Equal(t, ErrKeySizeWrong, err)
	pk, err = RSAPrivateKeyUnmarshalBinary(make([]byte, 12))
	assert.Error(t, err)
	assert.Nil(t, pk)
	assert.Equal(t, ErrKeySizeWrong, err)
	k, err := RSAPublicKeyUnmarshalBinary(make([]byte, RSA_MIN_KEY_SIZE-1))
	assert.Error(t, err)
	assert.Nil(t, k)
	assert.Equal(t, ErrKeySizeWrong, err)
}
