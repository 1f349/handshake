// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/1f349/handshake/crypto"
	"github.com/1f349/handshake/net/packets"
	"github.com/stretchr/testify/assert"
	"hash"
	"testing"
)

func kemTblTest(t *testing.T, tbl KemTableConfig, uuid1 [16]byte, uuid2 [16]byte, uuid3 [16]byte, hashProvider func() hash.Hash, k1 crypto.KemPublicKey,
	k2 crypto.KemPublicKey, k3 crypto.KemPublicKey, k4 crypto.KemPublicKey, k1bts []byte, k2bts []byte, k3bts []byte, k4bts []byte, adding bool) {
	t.Run("NotEmpty", func(t *testing.T) {
		if adding {
			t.Run("Add", func(t *testing.T) {
				assert.NoError(t, tbl.Add(k1, nil))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid1)
					assert.Nil(t, rk)
					assert.ErrorIs(t, err, ErrNoKey)
				})
				assert.NoError(t, tbl.Add(k2, &uuid1))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid1)
					assert.True(t, k2.Equals(rk))
					assert.Nil(t, err)
				})
				assert.NoError(t, tbl.Add(k2, &uuid2))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid2)
					assert.Nil(t, rk)
					assert.ErrorIs(t, err, ErrNoKey)
				})
			})
			t.Run("Import", func(t *testing.T) {
				assert.NoError(t, tbl.Import(k3bts, nil))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid1)
					assert.True(t, k2.Equals(rk))
					assert.Nil(t, err)
				})
				assert.NoError(t, tbl.Import(k4bts, &uuid2))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid2)
					assert.True(t, k4.Equals(rk))
					assert.Nil(t, err)
				})
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid1)
					assert.True(t, k2.Equals(rk))
					assert.Nil(t, err)
				})
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid3)
					assert.Nil(t, rk)
					assert.ErrorIs(t, err, ErrNoKey)
				})
			})
		} else {
			assert.NoError(t, tbl.SetRemoteKey(nil, uuid1))
			assert.NoError(t, tbl.SetRemoteKey(k2, uuid2))
			assert.NoError(t, tbl.SetRemoteKey(nil, uuid3))
		}
		t.Run("SetRemoteKey", func(t *testing.T) {
			t.Run("ValidKey", func(t *testing.T) {
				err := tbl.SetRemoteKey(k1, uuid1)
				assert.NoError(t, err)
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid1)
					assert.True(t, k1.Equals(rk))
					assert.Nil(t, err)
				})
			})
			t.Run("Nil", func(t *testing.T) {
				assert.NoError(t, tbl.SetRemoteKey(nil, uuid2))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid2)
					assert.Nil(t, rk)
					assert.ErrorIs(t, err, ErrNoKey)
				})
			})
		})
		t.Run("SetRemoteKeyData", func(t *testing.T) {
			t.Run("ValidKey", func(t *testing.T) {
				err := tbl.SetRemoteKeyData(k1bts, uuid2)
				assert.NoError(t, err)
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid2)
					assert.True(t, k1.Equals(rk))
					assert.Nil(t, err)
				})
				err = tbl.SetRemoteKeyData(k3bts, uuid1)
				assert.NoError(t, err)
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid1)
					assert.True(t, k3.Equals(rk))
					assert.Nil(t, err)
				})
			})
			t.Run("Nil", func(t *testing.T) {
				assert.NoError(t, tbl.SetRemoteKeyData(nil, uuid1))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid1)
					assert.ErrorIs(t, err, ErrNoKey)
					assert.Nil(t, rk)
				})
				assert.NoError(t, tbl.SetRemoteKeyData(k3bts, uuid1))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid1)
					assert.True(t, k3.Equals(rk))
					assert.Nil(t, err)
				})
				assert.NoError(t, tbl.SetRemoteKeyData(make([]byte, 0), uuid2))
				t.Run("GetRemoteKey", func(t *testing.T) {
					rk, err := tbl.GetRemoteKey(uuid2)
					assert.ErrorIs(t, err, ErrNoKey)
					assert.Nil(t, rk)
				})
			})
		})
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
		assert.NoError(t, tbl.SetRemoteKey(k1, uuid1))
	})
}

func TestKemTableConfig(t *testing.T) {
	uuid1 := packets.GetUUID()
	uuid2 := packets.GetUUID()
	uuid3 := packets.GetUUID()
	scheme := crypto.RSAKem4096Scheme
	hashProvider := sha256.New
	tbl := NewKemTableConfig(scheme, hashProvider)
	assert.NotNil(t, tbl)
	k1, _, k1bts := keyKemTest(t, scheme)
	k2, _, k2bts := keyKemTest(t, scheme)
	k3, _, k3bts := keyKemTest(t, scheme)
	k4, _, k4bts := keyKemTest(t, scheme)
	t.Run("Empty", func(t *testing.T) {
		t.Run("GetRemoteKey", func(t *testing.T) {
			rk, err := tbl.GetRemoteKey(uuid1)
			assert.Nil(t, rk)
			assert.ErrorIs(t, err, ErrNoKey)
			rk, err = tbl.GetRemoteKey(uuid2)
			assert.Nil(t, rk)
			assert.ErrorIs(t, err, ErrNoKey)
		})
		t.Run("Clear", func(t *testing.T) {
			tbl.Clear()
		})
		t.Run("SetRemoteKey", func(t *testing.T) {
			err := tbl.SetRemoteKey(k1, uuid1)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrNoKey)
			err = tbl.SetRemoteKeyData(k1bts, uuid1)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrNoKey)
			err = tbl.SetRemoteKey(k1, uuid2)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrNoKey)
			err = tbl.SetRemoteKeyData(k1bts, uuid2)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrNoKey)
		})
	})
	kemTblTest(t, tbl, uuid1, uuid2, uuid3, hashProvider, k1, k2, k3, k4, k1bts, k2bts, k3bts, k4bts, true)
	var cloned KemTableConfig
	t.Run("Clone", func(t *testing.T) {
		cloned = tbl.Clone()
	})
	t.Run("Cleared", func(t *testing.T) {
		tbl.Clear()
		t.Run("GetRemoteKey", func(t *testing.T) {
			rk, err := tbl.GetRemoteKey(uuid1)
			assert.Nil(t, rk)
			assert.ErrorIs(t, err, ErrNoKey)
		})
		t.Run("SetRemoteKey", func(t *testing.T) {
			err := tbl.SetRemoteKey(k1, uuid1)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrNoKey)
			err = tbl.SetRemoteKeyData(k1bts, uuid1)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrNoKey)
		})
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
		kemTblTest(t, cloned, uuid1, uuid2, uuid3, hashProvider, k1, k2, k3, k4, k1bts, k2bts, k3bts, k4bts, false)
	})
}
