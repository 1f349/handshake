// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
	"time"
)

var validPublicKeySignedPacketPayload *PublicKeySignedPacketPayload = nil
var validPublicKeySignedPacketPayloadKemPubKey crypto.KemPublicKey = nil
var validPublicKeySignedPacketPayloadSigPubKeyHash []byte = nil
var validPublicKeySignedPacketPayloadSigPubKey crypto.SigPublicKey = nil
var invalidPublicKeySignedPacketPayload *PublicKeySignedPacketPayload = nil

func GetValidPublicKeySignedPacketPayload() *PublicKeySignedPacketPayload {
	if validPublicKeySignedPacketPayload == nil {
		shash := sha256.New()
		scheme := crypto.RSAKem4096Scheme
		var err error
		validPublicKeySignedPacketPayloadKemPubKey, _, err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		kbts, err := validPublicKeySignedPacketPayloadKemPubKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		sigScheme := crypto.RSASig4096Scheme
		var pk crypto.SigPrivateKey
		validPublicKeySignedPacketPayloadSigPubKey, pk, err = sigScheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		skbts, err := validPublicKeySignedPacketPayloadSigPubKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		sigData := crypto.NewSigData(kbts, time.Now(), time.Now().Add(time.Hour), shash, pk)
		shash.Reset()
		shash.Write(skbts)
		validPublicKeySignedPacketPayloadSigPubKeyHash = shash.Sum(nil)
		validPublicKeySignedPacketPayload = &PublicKeySignedPacketPayload{SigPubKeyHash: validPublicKeySignedPacketPayloadSigPubKeyHash}
		err = validPublicKeySignedPacketPayload.Save(sigData)
		if err != nil {
			panic(err)
		}
	}
	return validPublicKeySignedPacketPayload
}

func GetInvalidPublicKeySignedPacketPayload() *PublicKeySignedPacketPayload {
	if invalidPublicKeySignedPacketPayload != nil {
		return invalidPublicKeySignedPacketPayload
	}
	invalidPublicKeySignedPacketPayload = &PublicKeySignedPacketPayload{SigPubKeyHash: []byte{0, 1, 2, 3}}
	return invalidPublicKeySignedPacketPayload
}

func TestValidPublicKeySignedPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetValidPublicKeySignedPacketPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &PublicKeySignedPacketPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	assert.True(t, slices.Equal(validPublicKeySignedPacketPayloadSigPubKeyHash, rPayload.SigPubKeyHash))
	sigData, err := rPayload.Load(validPublicKeySignedPacketPayloadKemPubKey)
	assert.NoError(t, err)
	assert.NotNil(t, sigData.Signature)
	if sigData.Signature != nil {
		assert.True(t, sigData.Verify(sha256.New(), validPublicKeySignedPacketPayloadSigPubKey))
	}
}

func TestInvalidPublicKeySignedPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInvalidPublicKeySignedPacketPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &PublicKeySignedPacketPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	sigData, err := rPayload.Load(validPublicKeySignedPacketPayloadKemPubKey)
	assert.True(t, slices.Equal([]byte{0, 1, 2, 3}, rPayload.SigPubKeyHash))
	assert.Error(t, err)
	assert.Nil(t, sigData.Signature)
}
