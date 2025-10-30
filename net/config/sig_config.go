// (C) 1f349 2025 - BSD-3-Clause License

package config

import "hash"

// SigConfig used to represent a signature to present to the other node
type SigConfig struct {
	Data    []byte
	Key     []byte
	keyHash []byte
}

// KeyHash generates from key data
func (sc *SigConfig) KeyHash(hash hash.Hash) []byte {
	if sc.keyHash == nil {
		hash.Reset()
		hash.Write(sc.Key)
		sc.keyHash = hash.Sum(nil)
	}
	return sc.keyHash
}
