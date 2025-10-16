// (C) 1f349 2025 - BSD-3-Clause License

package config

import (
	"github.com/1f349/handshake/crypto"
	"hash"
)

type NodeConfig struct {
	KEM             crypto.KemScheme
	HMACHash        hash.Hash
	KeySigCheckHash hash.Hash
}
