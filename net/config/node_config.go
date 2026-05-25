// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"github.com/1f349/handshake/crypto"
	"hash"
	"time"
)

// NodeConfig used to represent the local and remote config
type NodeConfig struct {
	KEM      crypto.KemScheme
	HMACHash func() hash.Hash
	// Used to compare for KEM and SIG Key hashes
	KeyCheckHash      func() hash.Hash
	KEMPrivateKeyData []byte
	kemPrivateKey     crypto.KemPrivateKey
	kemPublicKeyData  []byte
	kemPublicKeyHash  []byte
	// RequestLocalPublicKey provides 2(B) support on both sides
	RequestLocalPublicKey bool
	ValidDuration         time.Duration
	ConnID                [16]byte
}

func (nc *NodeConfig) Clone() *NodeConfig {
	nPKD := make([]byte, len(nc.KEMPrivateKeyData))
	copy(nPKD, nc.KEMPrivateKeyData)
	return &NodeConfig{
		KEM:                   nc.KEM,
		HMACHash:              nc.HMACHash,
		KeyCheckHash:          nc.KeyCheckHash,
		KEMPrivateKeyData:     nPKD,
		RequestLocalPublicKey: nc.RequestLocalPublicKey,
		ValidDuration:         nc.ValidDuration,
		ConnID:                nc.ConnID,
	}
}

func (nc *NodeConfig) SetPrivateKey(kemPrivateKey crypto.KemPrivateKey) (err error) {
	if kemPrivateKey != nil {
		nc.KEMPrivateKeyData, err = kemPrivateKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	nc.kemPublicKeyData = nil
	nc.kemPublicKeyHash = nil
	nc.kemPrivateKey = kemPrivateKey
	return
}

func (nc *NodeConfig) GetPrivateKey() crypto.KemPrivateKey {
	if nc.kemPrivateKey == nil {
		if nc.KEMPrivateKeyData == nil {
			return nil
		}
		var err error
		nc.kemPrivateKey, err = nc.KEM.UnmarshalBinaryPrivateKey(nc.KEMPrivateKeyData)
		if err != nil {
			return nil
		}
	}
	return nc.kemPrivateKey
}

// GetPublicKeyData of GetPrivateKey
func (nc *NodeConfig) GetPublicKeyData() []byte {
	if nc.kemPublicKeyData == nil {
		pkey := nc.GetPrivateKey()
		if pkey == nil {
			return nil
		}
		var err error
		nc.kemPublicKeyData, err = pkey.Public().MarshalBinary()
		if err != nil {
			return nil
		}
	}
	return nc.kemPublicKeyData
}

// GetPublicKeyHash generated from the GetPrivateKey's Public key
func (nc *NodeConfig) GetPublicKeyHash(hash hash.Hash) []byte {
	if nc.kemPublicKeyHash == nil {
		dat := nc.GetPublicKeyData()
		if dat == nil {
			return nil
		}
		nc.kemPublicKeyHash = crypto.HashBytes(dat, hash)
	}
	return nc.kemPublicKeyHash
}

// Valid checks KeyCheckHash, KEM, KEMPrivateKeyData and HMACHash are not nil and ValidDuration is >= time.Millisecond
func (nc *NodeConfig) Valid() bool {
	return nc.KeyCheckHash != nil && nc.KEM != nil && nc.KEMPrivateKeyData != nil && nc.HMACHash != nil && nc.ValidDuration >= time.Millisecond
}
