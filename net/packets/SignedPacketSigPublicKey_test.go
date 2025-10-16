// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

var validSignedPacketSigPublicKeyPayload *SignedPacketSigPublicKeyPayload = nil
var invalidSignedPacketSigPublicKeyPayload *SignedPacketSigPublicKeyPayload = nil

func GetValidSignedPacketSigPublicKeyPayload() *SignedPacketSigPublicKeyPayload {
	if validSignedPacketSigPublicKeyPayload == nil {
		validSignedPacketSigPublicKeyPayload = &SignedPacketSigPublicKeyPayload{}
		scheme := crypto.RSASig4096Scheme
		k, _, err := scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		err = validSignedPacketSigPublicKeyPayload.Save(k)
		if err != nil {
			panic(err)
		}
		return validSignedPacketSigPublicKeyPayload
	}
	return validSignedPacketSigPublicKeyPayload
}

func GetInvalidSignedPacketSigPublicKeyPayload() *SignedPacketSigPublicKeyPayload {
	if invalidSignedPacketSigPublicKeyPayload != nil {
		return invalidSignedPacketSigPublicKeyPayload
	}
	invalidSignedPacketSigPublicKeyPayload = &SignedPacketSigPublicKeyPayload{Data: []byte{0, 1, 2, 3}}
	return invalidSignedPacketSigPublicKeyPayload
}

func TestValidSignedPacketSigPublicKeyPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetValidSignedPacketSigPublicKeyPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &SignedPacketSigPublicKeyPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	k, err := rPayload.Load(crypto.RSASig4096Scheme)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	ko, err := payload.Load(nil)
	assert.NoError(t, err)
	assert.NotNil(t, ko)
	if k != nil && ko != nil {
		assert.True(t, ko.Equals(k))
	}
}

func TestInvalidSignedPacketSigPublicKeyPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInvalidSignedPacketSigPublicKeyPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &SignedPacketSigPublicKeyPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	k, err := rPayload.Load(crypto.RSASig4096Scheme)
	assert.Error(t, err)
	assert.Nil(t, k)
}
