// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"github.com/1f349/handshake/crypto"
	"hash"
	"sync"
)

// SigVerifierTableConfig provides a configuration table of known SigPublicKeys
type SigVerifierTableConfig interface {
	Import(publicKeyData []byte) error
	Add(publicKey crypto.SigPublicKey) error
	Clear()
	// FindFromHash of the public key data
	FindFromHash(hash []byte) (crypto.SigPublicKey, error)
	// Find the key from public key data
	Find(publicKeyData []byte) (crypto.SigPublicKey, error)
	Clone() SigVerifierTableConfig
}

// NewSigVerifierTableConfig with the specified SigScheme and hashProvider for public key data processing
func NewSigVerifierTableConfig(schema crypto.SigScheme, hashProvider func() hash.Hash) SigVerifierTableConfig {
	return &sigVerifierTableConfig{schema: schema, store: make(map[string]*crypto.SigPublicKey), hash: hashProvider(), hashProvider: hashProvider}
}

type sigVerifierTableConfig struct {
	hash         hash.Hash
	hashProvider func() hash.Hash
	schema       crypto.SigScheme
	lock         sync.RWMutex
	store        map[string]*crypto.SigPublicKey
}

func (k *sigVerifierTableConfig) Clone() SigVerifierTableConfig {
	k.lock.RLock()
	defer k.lock.RUnlock()
	ntbl := &sigVerifierTableConfig{schema: k.schema, store: make(map[string]*crypto.SigPublicKey), hash: k.hashProvider(), hashProvider: k.hashProvider}
	for k, v := range k.store {
		ntbl.store[k] = v
	}
	return ntbl
}

func (k *sigVerifierTableConfig) add(publicKey crypto.SigPublicKey, publicKeyData []byte) {
	k.lock.Lock()
	defer k.lock.Unlock()
	hsh := crypto.HashBytes(publicKeyData, k.hash)
	if kf, found := k.store[string(hsh)]; found {
		if kf != nil && publicKey.Equals(*kf) {
			return
		}
		k.store[string(hsh)] = nil
	} else {
		k.store[string(hsh)] = &publicKey
	}
	k.store[string(publicKeyData)] = &publicKey
}

func (k *sigVerifierTableConfig) Import(publicKeyData []byte) error {
	pk, err := k.schema.UnmarshalBinaryPublicKey(publicKeyData)
	if err != nil {
		return err
	}
	k.add(pk, publicKeyData)
	return nil
}

func (k *sigVerifierTableConfig) Add(publicKey crypto.SigPublicKey) error {
	pk, err := publicKey.MarshalBinary()
	if err != nil {
		return err
	}
	k.add(publicKey, pk)
	return nil
}

func (k *sigVerifierTableConfig) Clear() {
	k.lock.Lock()
	defer k.lock.Unlock()
	k.store = make(map[string]*crypto.SigPublicKey)
}

// FindFromHash of the public key data
func (k *sigVerifierTableConfig) FindFromHash(hash []byte) (crypto.SigPublicKey, error) {
	if len(hash) != k.hash.Size() {
		return nil, ErrHashSizeMismatch
	}
	k.lock.RLock()
	defer k.lock.RUnlock()
	pk, found := k.store[string(hash)]
	if found {
		if pk == nil {
			return nil, ErrMultipleKeys
		} else {
			return *pk, nil
		}
	}
	return nil, ErrNoKey
}

// Find the key from public key data
func (k *sigVerifierTableConfig) Find(publicKeyData []byte) (crypto.SigPublicKey, error) {
	k.lock.RLock()
	defer k.lock.RUnlock()
	pk, found := k.store[string(publicKeyData)]
	if found {
		if pk == nil {
			return nil, ErrMultipleKeys
		} else {
			return *pk, nil
		}
	}
	return nil, ErrNoKey
}
