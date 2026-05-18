// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"errors"
	"github.com/1f349/handshake/crypto"
	"hash"
	"sync"
)

// ErrMultipleKeys when multiple keys for a provided hash are found
var ErrMultipleKeys = errors.New("multiple keys for hash")

// ErrNoKey when no key is found
var ErrNoKey = errors.New("no key found")

// KemTableConfig provides a configuration table of known KemPublicKeys
type KemTableConfig struct {
	hash         hash.Hash
	hashProvider func() hash.Hash
	schema       crypto.KemScheme
	lock         sync.RWMutex
	store        map[string]*crypto.KemPublicKey
}

// NewKemTableConfig with the specified KemScheme and hashProvider for public key data processing
func NewKemTableConfig(schema crypto.KemScheme, hashProvider func() hash.Hash) *KemTableConfig {
	return &KemTableConfig{schema: schema, store: make(map[string]*crypto.KemPublicKey), hash: hashProvider(), hashProvider: hashProvider}
}

func (k *KemTableConfig) add(publicKey crypto.KemPublicKey, publicKeyData []byte) {
	k.lock.Lock()
	defer k.lock.Unlock()
	k.hash.Reset()
	k.hash.Write(publicKeyData)
	hsh := k.hash.Sum(nil)
	if _, found := k.store[string(hsh)]; found {
		k.store[string(hsh)] = nil
	} else {
		k.store[string(hsh)] = &publicKey
	}
	k.store[string(publicKeyData)] = &publicKey
}

func (k *KemTableConfig) Import(publicKeyData []byte) error {
	pk, err := k.schema.UnmarshalBinaryPublicKey(publicKeyData)
	if err != nil {
		return err
	}
	k.add(pk, publicKeyData)
	return nil
}

func (k *KemTableConfig) Add(publicKey crypto.KemPublicKey) error {
	pk, err := publicKey.MarshalBinary()
	if err != nil {
		return err
	}
	k.add(publicKey, pk)
	return nil
}

func (k *KemTableConfig) Clear() {
	k.lock.Lock()
	defer k.lock.Unlock()
	k.store = make(map[string]*crypto.KemPublicKey)
}

// FindFromHash of the public key data
func (k *KemTableConfig) FindFromHash(publicKeyData []byte) (crypto.KemPublicKey, error) {
	k.lock.RLock()
	defer k.lock.RUnlock()
	hp := k.hashProvider()
	hp.Reset()
	hp.Write(publicKeyData)
	pk, found := k.store[string(hp.Sum(nil))]
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
func (k *KemTableConfig) Find(publicKeyData []byte) (crypto.KemPublicKey, error) {
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
