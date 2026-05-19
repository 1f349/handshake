// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"bytes"
	"errors"
	intbyteutils "github.com/1f349/int-byte-utils"
	"hash"
	"io"
	"time"
)

var ErrKeyNil = errors.New("key is nil")

// GetSignedDataPayload gets the signature data payload for signing; if hash is nil, the data itself is provided rather than its hash
func GetSignedDataPayload(publicKey []byte, issueTime, expiryTime time.Time, hash hash.Hash) []byte {
	if expiryTime.Before(issueTime) || expiryTime.Equal(issueTime) {
		return nil
	}
	buff := bytes.NewBuffer(make([]byte, 0, len(publicKey)+20))
	buff.Write(publicKey)
	if issueTime.UnixMilli() < 0 {
		return nil
	}
	_, err := intbyteutils.WriteUintAsBytes(uint(issueTime.UnixMilli()), buff)
	if err != nil {
		return nil
	}
	if expiryTime.UnixMilli() < 0 {
		return nil
	}
	_, err = intbyteutils.WriteUintAsBytes(uint(expiryTime.UnixMilli()), buff)
	if err != nil {
		return nil
	}
	if hash != nil {
		return HashBytes(buff.Bytes(), hash)
	}
	return buff.Bytes()
}

// NewSigData creates a new SigData instance given the information for GetSignedDataPayload and the SigPrivateKey for signing
func NewSigData(publicEKey []byte, issueTime, expiryTime time.Time, hash hash.Hash, privateKey SigPrivateKey) *SigData {
	if expiryTime.Before(issueTime) {
		return nil
	}
	dat := GetSignedDataPayload(publicEKey, issueTime, expiryTime, hash)
	if dat == nil {
		return nil
	}
	sig, err := privateKey.Scheme().Sign(privateKey, dat)
	if err != nil {
		return nil
	}
	return &SigData{
		PublicKey:  publicEKey,
		Signature:  sig,
		IssueTime:  time.UnixMilli(issueTime.UnixMilli()),
		ExpiryTime: time.UnixMilli(expiryTime.UnixMilli()),
	}
}

func UnmarshalSigData(data, publicEKey []byte) (*SigData, error) {
	sd := &SigData{PublicKey: publicEKey}
	err := sd.UnmarshalBinary(data)
	return sd, err
}

// SigData provides a certificate like verification object for public keys
type SigData struct {
	PublicKey  []byte
	Signature  []byte
	IssueTime  time.Time
	ExpiryTime time.Time
}

func (s *SigData) UnmarshalBinary(data []byte) (err error) {
	buff := bytes.NewBuffer(data)
	_, err, sl := intbyteutils.ReadUintFromBytes(buff)
	if err != nil {
		return err
	}
	s.Signature = make([]byte, sl)
	_, err = io.ReadFull(buff, s.Signature)
	if err != nil {
		return err
	}
	_, err, ite := intbyteutils.ReadUintFromBytes(buff)
	if err != nil {
		return err
	}
	s.IssueTime = time.UnixMilli(int64(ite))
	_, err, ete := intbyteutils.ReadUintFromBytes(buff)
	if err != nil {
		return err
	}
	s.ExpiryTime = time.UnixMilli(int64(ete))
	return nil
}

func (s *SigData) MarshalBinary() (data []byte, err error) {
	buff := bytes.NewBuffer(make([]byte, 0, len(s.Signature)+20))
	_, err = intbyteutils.WriteUintAsBytes(uint(len(s.Signature)), buff)
	if err != nil {
		return nil, err
	}
	buff.Write(s.Signature)
	_, err = intbyteutils.WriteUintAsBytes(uint(s.IssueTime.UnixMilli()), buff)
	if err != nil {
		return nil, err
	}
	_, err = intbyteutils.WriteUintAsBytes(uint(s.ExpiryTime.UnixMilli()), buff)
	if err != nil {
		return nil, err
	}
	return buff.Bytes(), nil
}

// Verify the SigData given the signed data payload hash.Hash and the SigPublicKey to check against
func (s *SigData) Verify(hash hash.Hash, pubKey SigPublicKey) bool {
	if pubKey == nil || s.PublicKey == nil ||
		s.IssueTime.After(time.Now()) || s.ExpiryTime.Before(time.Now()) || s.ExpiryTime.Equal(time.Now()) {
		return false
	}
	d := GetSignedDataPayload(s.PublicKey, s.IssueTime, s.ExpiryTime, hash)
	if d == nil {
		return false
	}
	b, err := pubKey.Scheme().Verify(pubKey, d, s.Signature)
	if err != nil {
		return false
	}
	return b
}
