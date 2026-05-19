// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"github.com/1f349/handshake/crypto"
	"hash"
)

// SigVerifierConfig used to represent a verification key to check received singatures
type SigVerifierConfig struct {
	SigDataHash   func() hash.Hash
	Scheme        crypto.SigScheme
	PublicKeyData []byte
	publicKeyHash []byte
	publicKey     crypto.SigPublicKey
}

// PublicKeyHash generates from public key data
func (svc *SigVerifierConfig) PublicKeyHash(hash hash.Hash) []byte {
	if svc.publicKeyHash == nil {
		svc.publicKeyHash = crypto.HashBytes(svc.PublicKeyData, hash)
	}
	return svc.publicKeyHash
}

// PublicKey constructed from public key data, nil on failure
func (svc *SigVerifierConfig) PublicKey() crypto.SigPublicKey {
	if svc.publicKey == nil {
		var err error
		svc.publicKey, err = svc.Scheme.UnmarshalBinaryPublicKey(svc.PublicKeyData)
		if err != nil {
			return nil
		}
	}
	return svc.publicKey
}

// Valid checks if SigDataHash, Scheme and PublicKeyData fields are not nil; does not check signature validation
func (svc *SigVerifierConfig) Valid() bool {
	return svc.SigDataHash != nil && svc.Scheme != nil && svc.PublicKeyData != nil
}
