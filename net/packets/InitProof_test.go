// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

type initProofTestID int

const (
	initProofTestValid initProofTestID = iota
	initProofTestInvalidEncapsulation
	initProofTestInvalidHMAC
	initProofTestInvalid
)

var initProofKeys = [4]crypto.KemPrivateKey{}
var InitProofSecrets = [4][]byte{}
var initProofPayloads = [4]*InitProofPayload{}

func GetInitProofKey(id initProofTestID) crypto.KemPrivateKey {
	if initProofKeys[id] == nil {
		scheme := crypto.RSAKem4096Scheme
		var err error
		_, initProofKeys[id], err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		switch id {
		case initProofTestValid:
			initProofKeys[initProofTestInvalidHMAC] = initProofKeys[id]
		case initProofTestInvalidHMAC:
			initProofKeys[initProofTestValid] = initProofKeys[id]
		case initProofTestInvalid:
			initProofKeys[initProofTestInvalidEncapsulation] = initProofKeys[id]
		case initProofTestInvalidEncapsulation:
			initProofKeys[initProofTestInvalid] = initProofKeys[id]
		}
	}
	return initProofKeys[id]
}

func GetInitProofPayload(id initProofTestID) *InitProofPayload {
	if initProofPayloads[id] == nil {
		switch id {
		case initProofTestValid, initProofTestInvalidEncapsulation:
			initProofPayloads[id] = &InitProofPayload{ProofHMAC: sha256.New().Sum(nil)}
		default:
			initProofPayloads[id] = &InitProofPayload{}
		}
		var err error
		InitProofSecrets[id], err = initProofPayloads[id].Encapsulate(GetInitProofKey(id).Public())
		if err != nil {
			panic(err)
		}
	}
	return initProofPayloads[id]
}

func TestValidInitProofPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitProofPayload(initProofTestValid)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitProofPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, payload.ProofHMAC, rPayload.ProofHMAC)
	cs, err := rPayload.Decapsulate(GetInitProofKey(initProofTestValid))
	assert.NoError(t, err)
	assert.Equal(t, InitProofSecrets[initProofTestValid], cs)
}

func TestInvalidEncapsulationInitProofPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitProofPayload(initProofTestInvalidEncapsulation)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitProofPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, payload.ProofHMAC, rPayload.ProofHMAC)
	cs, err := rPayload.Decapsulate(GetInitProofKey(initProofTestValid))
	assert.NoError(t, err)
	assert.NotEqual(t, InitProofSecrets[initProofTestInvalidEncapsulation], cs)
}

func TestInvalidHMACInitProofPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitProofPayload(initProofTestInvalidHMAC)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitProofPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, []byte{}, rPayload.ProofHMAC)
	assert.Nil(t, payload.ProofHMAC)
	assert.NotNil(t, rPayload.ProofHMAC)
	cs, err := rPayload.Decapsulate(GetInitProofKey(initProofTestInvalidHMAC))
	assert.NoError(t, err)
	assert.Equal(t, InitProofSecrets[initProofTestInvalidHMAC], cs)
}

func TestInvalidInitProofPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInitProofPayload(initProofTestInvalid)
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &InitProofPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.Size(), rPayload.Size())
	assert.Equal(t, []byte{}, rPayload.ProofHMAC)
	assert.Nil(t, payload.ProofHMAC)
	assert.NotNil(t, rPayload.ProofHMAC)
	cs, err := rPayload.Decapsulate(GetInitProofKey(initProofTestValid))
	assert.NoError(t, err)
	assert.NotEqual(t, InitProofSecrets[initProofTestInvalid], cs)
}
