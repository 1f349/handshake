// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"github.com/1f349/handshake/crypto"
	"hash"
)

// SigConfig used to represent a signature to present to the other node
type SigConfig struct {
	Data    []byte
	Key     []byte
	keyHash []byte
}

// KeyHash generates from key data
func (sc *SigConfig) KeyHash(hash hash.Hash) []byte {
	if sc.keyHash == nil {
		sc.keyHash = crypto.HashBytes(sc.Key, hash)
	}
	return sc.keyHash
}

// Valid checks if Data and Key fields are not nil; does not check signature validation
func (sc *SigConfig) Valid() bool {
	return sc.Key != nil && sc.Data != nil
}
