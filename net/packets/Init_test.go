// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

type initTestID int

const (
	initTestValid2 initTestID = iota
	initTestValid2B
	initTestValid2A
	initTestValid2AB
	initTestInvalid2
	initTestInvalid2B
)

var validInitKey crypto.KemPrivateKey
var invalidInitKey crypto.KemPrivateKey
var initPacketPayloads = [6]*InitPayload{}
var InitSecrets = [6][]byte{}

func GetInitKey(id initTestID) crypto.KemPrivateKey {
	scheme := crypto.RSAKem4096Scheme
	switch id {
	case initTestInvalid2, initTestInvalid2B:
		if invalidInitKey == nil {
			var err error
			_, invalidInitKey, err = scheme.GenerateKeyPair()
			if err != nil {
				panic(err)
			}
		}
		return invalidInitKey
	default:
		if validInitKey == nil {
			var err error
			_, validInitKey, err = scheme.GenerateKeyPair()
			if err != nil {
				panic(err)
			}
		}
		return validInitKey
	}
}
func GetInitPayload(id initTestID) *InitPayload {
	if initPacketPayloads[id] == nil {
		switch id {
		case initTestValid2B, initTestValid2AB, initTestInvalid2B:
			initPacketPayloads[id] = &InitPayload{}
		default:
			initPacketPayloads[id] = &InitPayload{PublicKeyHash: sha256.New().Sum(nil)}
		}
		if id != initTestValid2A && id != initTestValid2AB {
			var err error
			InitSecrets[id], err = initPacketPayloads[id].Encapsulate(GetInitKey(id).Public())
			if err != nil {
				panic(err)
			}
		}
	}
	return initPacketPayloads[id]
}

func TestValid2InitPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitPayload(initTestValid2)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, payload.PublicKeyHash, rPayload.PublicKeyHash)
	cs, err := rPayload.Decapsulate(GetInitKey(initTestValid2))
	assert.NoError(t, err)
	assert.Equal(t, InitSecrets[initTestValid2], cs)
}

func TestValid2BInitPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitPayload(initTestValid2B)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, []byte{}, rPayload.PublicKeyHash)
	assert.Nil(t, payload.PublicKeyHash)
	assert.NotNil(t, rPayload.PublicKeyHash)
	cs, err := rPayload.Decapsulate(GetInitKey(initTestValid2B))
	assert.NoError(t, err)
	assert.Equal(t, InitSecrets[initTestValid2B], cs)
}

func TestValid2AInitPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitPayload(initTestValid2A)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, payload.PublicKeyHash, rPayload.PublicKeyHash)
	cs, err := rPayload.Decapsulate(GetInitKey(initTestValid2A))
	assert.Error(t, err)
	assert.Equal(t, ErrNoEncapsulation, err)
	assert.Nil(t, cs)
}

func TestValid2ABInitPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitPayload(initTestValid2AB)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, []byte{}, rPayload.PublicKeyHash)
	assert.Nil(t, payload.PublicKeyHash)
	assert.NotNil(t, rPayload.PublicKeyHash)
	cs, err := rPayload.Decapsulate(GetInitKey(initTestValid2AB))
	assert.Error(t, err)
	assert.Equal(t, ErrNoEncapsulation, err)
	assert.Nil(t, cs)
}

func TestInvalid2InitPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitPayload(initTestInvalid2)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, payload.PublicKeyHash, rPayload.PublicKeyHash)
	cs, err := rPayload.Decapsulate(GetInitKey(initTestValid2))
	assert.NoError(t, err)
	assert.NotEqual(t, InitSecrets[initTestInvalid2], cs)
}

func TestInvalid2BInitPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitPayload(initTestInvalid2B)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, []byte{}, rPayload.PublicKeyHash)
	assert.Nil(t, payload.PublicKeyHash)
	assert.NotNil(t, rPayload.PublicKeyHash)
	cs, err := rPayload.Decapsulate(GetInitKey(initTestValid2B))
	assert.NoError(t, err)
	assert.NotEqual(t, InitSecrets[initTestInvalid2B], cs)
}
