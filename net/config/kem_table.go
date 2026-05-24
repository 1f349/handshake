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

// ErrHashSizeMismatch when the provided hash is not the same as the hash used by the table
var ErrHashSizeMismatch = errors.New("hash size mismatch")

// KemTableConfig provides a configuration table of known KemPublicKeys
type KemTableConfig interface {
	Import(publicKeyData []byte, remoteKey bool) error
	Add(publicKey crypto.KemPublicKey, remoteKey bool) error
	Clear()
	// FindFromHash of the public key data
	FindFromHash(hash []byte) (crypto.KemPublicKey, error)
	// Find the key from public key data
	Find(publicKeyData []byte) (crypto.KemPublicKey, error)
	// SetRemoteKeyData also allows nil / len(0) byte slice to clear
	SetRemoteKeyData(remotePublicKeyData []byte) error
	// SetRemoteKey also allows nil to clear
	SetRemoteKey(publicKey crypto.KemPublicKey) error
	GetRemoteKey() (crypto.KemPublicKey, error)
}

// NewKemTableConfig with the specified KemScheme and hashProvider for public key data processing
func NewKemTableConfig(schema crypto.KemScheme, hashProvider func() hash.Hash) KemTableConfig {
	return &kemTableConfig{schema: schema, store: make(map[string]*crypto.KemPublicKey), hash: hashProvider()}
}

type kemTableConfig struct {
	hash                hash.Hash
	schema              crypto.KemScheme
	lock                sync.RWMutex
	store               map[string]*crypto.KemPublicKey
	remotePublicKeyData string
}

// SetRemoteKeyData also allows nil / len(0) byte slice to clear
func (k *kemTableConfig) SetRemoteKeyData(remotePublicKeyData []byte) error {
	k.lock.Lock()
	defer k.lock.Unlock()
	if len(remotePublicKeyData) == 0 {
		k.remotePublicKeyData = ""
		return nil
	}
	if string(remotePublicKeyData) == k.remotePublicKeyData {
		return nil
	}
	if _, found := k.store[string(remotePublicKeyData)]; !found {
		return ErrNoKey
	}
	k.remotePublicKeyData = string(remotePublicKeyData)
	return nil
}

// SetRemoteKey also allows nil to clear
func (k *kemTableConfig) SetRemoteKey(publicKey crypto.KemPublicKey) error {
	if publicKey == nil {
		k.lock.Lock()
		defer k.lock.Unlock()
		k.remotePublicKeyData = ""
		return nil
	}
	remotePublicKeyData, err := publicKey.MarshalBinary()
	if err != nil {
		return err
	}
	return k.SetRemoteKeyData(remotePublicKeyData)
}

func (k *kemTableConfig) GetRemoteKey() (crypto.KemPublicKey, error) {
	k.lock.RLock()
	defer k.lock.RUnlock()
	if fk, found := k.store[k.remotePublicKeyData]; found && fk != nil {
		return *fk, nil
	} else {
		return nil, ErrNoKey
	}
}

func (k *kemTableConfig) add(publicKey crypto.KemPublicKey, publicKeyData []byte, remoteKey bool) {
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
	if remoteKey {
		k.remotePublicKeyData = string(publicKeyData)
	}
}

func (k *kemTableConfig) Import(publicKeyData []byte, remoteKey bool) error {
	pk, err := k.schema.UnmarshalBinaryPublicKey(publicKeyData)
	if err != nil {
		return err
	}
	k.add(pk, publicKeyData, remoteKey)
	return nil
}

func (k *kemTableConfig) Add(publicKey crypto.KemPublicKey, remoteKey bool) error {
	pk, err := publicKey.MarshalBinary()
	if err != nil {
		return err
	}
	k.add(publicKey, pk, remoteKey)
	return nil
}

func (k *kemTableConfig) Clear() {
	k.lock.Lock()
	defer k.lock.Unlock()
	k.store = make(map[string]*crypto.KemPublicKey)
	k.remotePublicKeyData = ""
}

// FindFromHash of the public key data
func (k *kemTableConfig) FindFromHash(hash []byte) (crypto.KemPublicKey, error) {
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
func (k *kemTableConfig) Find(publicKeyData []byte) (crypto.KemPublicKey, error) {
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
