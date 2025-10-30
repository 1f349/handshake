// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"testing"
)

var ValidFinalProofPayload = &FinalProofPayload{ProofHMAC: sha256.New().Sum(nil)}
var InvalidFinalProofPayload = &FinalProofPayload{ProofHMAC: nil}

func TestValidFinalProofPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := ValidFinalProofPayload
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(sha256.New().Size()+1), n)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &FinalProofPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(sha256.New().Size()+1), n)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, payload.ProofHMAC, rPayload.ProofHMAC)
}

func TestInvalidFinalProofPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := InvalidFinalProofPayload
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), n)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &FinalProofPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), n)
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, []byte{}, rPayload.ProofHMAC)
	assert.Nil(t, payload.ProofHMAC)
	assert.NotNil(t, rPayload.ProofHMAC)
}
