// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

var validPublicKeyPayload *PublicKeyPayload = nil
var invalidPublicKeyPayload *PublicKeyPayload = nil

func GetValidPublicKeyPayload() *PublicKeyPayload {
	if validPublicKeyPayload == nil {
		validPublicKeyPayload = &PublicKeyPayload{}
		scheme := crypto.RSAKem4096Scheme
		k, _, err := scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		err = validPublicKeyPayload.Save(k)
		if err != nil {
			panic(err)
		}
	}
	return validPublicKeyPayload
}

func GetInvalidPublicKeyPayload() *PublicKeyPayload {
	if invalidPublicKeyPayload != nil {
		return invalidPublicKeyPayload
	}
	invalidPublicKeyPayload = &PublicKeyPayload{Data: []byte{0, 1, 2, 3}}
	return invalidPublicKeyPayload
}

func TestValidPublicKeyPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetValidPublicKeyPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &PublicKeyPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	k, err := rPayload.Load(crypto.RSAKem4096Scheme)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	ko, err := payload.Load(nil)
	assert.NoError(t, err)
	assert.NotNil(t, ko)
	if k != nil && ko != nil {
		assert.True(t, ko.Equals(k))
	}
}

func TestInvalidPublicKeyPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInvalidPublicKeyPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &PublicKeyPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	k, err := rPayload.Load(crypto.RSAKem4096Scheme)
	assert.Error(t, err)
	assert.Nil(t, k)
}
