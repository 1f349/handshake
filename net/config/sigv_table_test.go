// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"hash"
	"testing"
)

func sigTblTest(t *testing.T, tbl SigVerifierTableConfig, hashProvider func() hash.Hash, k1 crypto.SigPublicKey,
	k2 crypto.SigPublicKey, k1bts []byte, k2bts []byte, k3bts []byte, k4bts []byte, adding bool) {
	t.Run("NotEmpty", func(t *testing.T) {
		if adding {
			t.Run("Add", func(t *testing.T) {
				assert.NoError(t, tbl.Add(k1))
				assert.NoError(t, tbl.Add(k2))
				assert.NoError(t, tbl.Add(k2))
			})
			t.Run("Import", func(t *testing.T) {
				assert.NoError(t, tbl.Import(k3bts))
				assert.NoError(t, tbl.Import(k4bts))
			})
		}
		t.Run("Find", func(t *testing.T) {
			fk, err := tbl.Find(k2bts)
			assert.NoError(t, err)
			assert.NotNil(t, fk)
			assert.True(t, k2.Equals(fk))
		})
		t.Run("FindFromHash", func(t *testing.T) {
			t.Run("ErrHashSizeMismatch", func(t *testing.T) {
				fk, err := tbl.FindFromHash([]byte{1, 2})
				assert.Nil(t, fk)
				assert.ErrorIs(t, err, ErrHashSizeMismatch)
			})
			t.Run("ValidHash", func(t *testing.T) {
				fk, err := tbl.FindFromHash(crypto.HashBytes(k1bts, hashProvider()))
				assert.NotNil(t, fk)
				if errors.Is(err, ErrMultipleKeys) {
					t.Log("Key Hash Collision Found") // Rare so hash for example data!
					t.Log(base64.StdEncoding.EncodeToString(k1bts))
					t.Log(base64.StdEncoding.EncodeToString(crypto.HashBytes(k1bts, hashProvider())))
					t.Log(base64.StdEncoding.EncodeToString(k2bts))
					t.Log(base64.StdEncoding.EncodeToString(crypto.HashBytes(k2bts, hashProvider())))
					t.Log(base64.StdEncoding.EncodeToString(k3bts))
					t.Log(base64.StdEncoding.EncodeToString(crypto.HashBytes(k3bts, hashProvider())))
					t.Log(base64.StdEncoding.EncodeToString(k4bts))
					t.Log(base64.StdEncoding.EncodeToString(crypto.HashBytes(k4bts, hashProvider())))
					t.Run("Find", func(t *testing.T) {
						fk, err = tbl.Find(k1bts)
						assert.NoError(t, err)
						assert.NotNil(t, fk)
						assert.True(t, k1.Equals(fk))
					})
				} else {
					assert.NoError(t, err)
					assert.True(t, k1.Equals(fk))
				}
			})
		})
	})
}

func TestSigTableConfig(t *testing.T) {
	scheme := crypto.RSASig4096Scheme
	hashProvider := sha256.New
	tbl := NewSigVerifierTableConfig(scheme, hashProvider)
	assert.NotNil(t, tbl)
	k1, _, k1bts := keySigTest(t, scheme)
	k2, _, k2bts := keySigTest(t, scheme)
	_, _, k3bts := keySigTest(t, scheme)
	_, _, k4bts := keySigTest(t, scheme)
	t.Run("Empty", func(t *testing.T) {
		t.Run("Clear", func(t *testing.T) {
			tbl.Clear()
		})
	})
	sigTblTest(t, tbl, hashProvider, k1, k2, k1bts, k2bts, k3bts, k4bts, true)
	var cloned SigVerifierTableConfig
	t.Run("Clone", func(t *testing.T) {
		cloned = tbl.Clone()
	})
	t.Run("Cleared", func(t *testing.T) {
		tbl.Clear()
		t.Run("Find", func(t *testing.T) {
			fk, err := tbl.Find(k1bts)
			assert.ErrorIs(t, err, ErrNoKey)
			assert.Nil(t, fk)
		})
		t.Run("FindFromHash", func(t *testing.T) {
			t.Run("ErrHashSizeMismatch", func(t *testing.T) {
				fk, err := tbl.FindFromHash([]byte{1, 2})
				assert.Nil(t, fk)
				assert.ErrorIs(t, err, ErrHashSizeMismatch)
			})
			t.Run("ValidHash", func(t *testing.T) {
				fk, err := tbl.FindFromHash(crypto.HashBytes(k1bts, hashProvider()))
				assert.Nil(t, fk)
				assert.ErrorIs(t, err, ErrNoKey)
			})
		})
	})
	t.Run("Cloned", func(t *testing.T) {
		sigTblTest(t, cloned, hashProvider, k1, k2, k1bts, k2bts, k3bts, k4bts, false)
	})
}
