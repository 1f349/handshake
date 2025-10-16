// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"hash"
	"testing"
	"time"
)

func TestSigData(t *testing.T) {
	scheme := RSASig4096Scheme
	pk, k, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	processTestSigData(t, k, pk, false)
}

func TestSigDataWrongKey(t *testing.T) {
	scheme := RSASig4096Scheme
	pk, _, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	_, k, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	assert.False(t, k.Public().Equals(pk))
	processTestSigData(t, k, pk, true)
}

func processTestSigData(t *testing.T, k SigPrivateKey, pk SigPublicKey, allFail bool) {
	tHash := sha256.New()
	kScheme := RSAKem4096Scheme
	sk, _, err := kScheme.GenerateKeyPair()
	assert.NoError(t, err)
	skb, err := sk.MarshalBinary()
	assert.NoError(t, err)
	sigs := make([][]byte, 0, 9)
	sigs = append(sigs, []byte{})                                                                                           // Empty Data
	sigs = append(sigs, damageBytes(getSigData(t, NewSigData(skb, time.Now(), time.Now().Add(time.Hour), tHash, k))))       // Damaged data
	sigs = append(sigs, getSigData(t, damageMeta(NewSigData(skb, time.Now(), time.Now().Add(time.Hour), tHash, k))))        // Damaged meta
	sigs = append(sigs, getSigData(t, NewSigData(skb, time.Now().Add(time.Hour), time.Now().Add(time.Hour*2), tHash, k)))   // Not yet valid
	sigs = append(sigs, getSigData(t, NewSigData(skb, time.Now().Add(-time.Hour), time.Now().Add(-time.Minute), tHash, k))) // Expired
	sigs = append(sigs, getSigData(t, NewSigData(skb, time.Now().Add(time.Hour), time.Now().Add(time.Hour*2), nil, k)))     // Not yet valid (Full data)
	sigs = append(sigs, getSigData(t, NewSigData(skb, time.Now().Add(-time.Hour), time.Now().Add(-time.Minute), nil, k)))   // Expired (Full data)
	sigs = append(sigs, getSigData(t, NewSigData(skb, time.Now(), time.Now().Add(time.Minute*5), tHash, k)))                // Valid
	sigs = append(sigs, getSigData(t, NewSigData(skb, time.Now(), time.Now().Add(time.Minute*5), nil, k)))                  // Valid (Full data)
	var results = []bool{false, false, false, false, false, false, false, true, true}
	var hashes = []hash.Hash{nil, tHash, tHash, tHash, tHash, nil, nil, tHash, nil}
	var name = []string{"Empty Data", "Damaged data", "Damaged meta", "Not yet valid", "Expired", "Not yet valid (Full data)", "Expired (Full data)", "Valid", "Valid (Full data)"}
	if allFail {
		for idx := range name {
			name[idx] = name[idx] + " Wrong Key"
		}
	}
	for idx, s := range sigs {
		t.Run(name[idx], func(t *testing.T) {
			sData := &SigData{PublicKey: skb}
			err := sData.UnmarshalBinary(s)
			if idx == 0 {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if allFail {
				assert.False(t, sData.Verify(hashes[idx], pk))
			} else {
				assert.Equal(t, results[idx], sData.Verify(hashes[idx], pk))
			}
		})
	}
}

func getSigData(t *testing.T, d *SigData) []byte {
	assert.NotNil(t, d)
	bts, err := d.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, bts)
	return bts
}

func damageBytes(bts []byte) []byte {
	if len(bts) > 12 {
		bts[11] = ^bts[11]
	}
	return bts
}

func damageMeta(d *SigData) *SigData {
	if d == nil {
		return nil
	}
	d.ExpiryTime = d.ExpiryTime.Add(-time.Minute)
	return d
}
