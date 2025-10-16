// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"github.com/1f349/handshake/crypto"
	intbyteutils "github.com/1f349/int-byte-utils"
	"hash"
	"io"
)

const PublicKeyDataPacketType = PacketType(6)

type PublicKeyPayload struct {
	Data []byte
	key  crypto.KemPublicKey
}

func (p *PublicKeyPayload) MarshalHashCalculator() hash.Hash {
	return nil
}

func (p *PublicKeyPayload) SetCompleteHash([]byte) {
}

func (p *PublicKeyPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := writeBuff(w, p.Data)
	return int64(m), err
}

func (p *PublicKeyPayload) ReadFrom(r io.Reader) (n int64, err error) {
	var m int
	m, err, p.Data = readBuff(r)
	return int64(m), err
}

func (p *PublicKeyPayload) Size() uint {
	return uint(intbyteutils.LenUintAsBytes(uint(len(p.Data))) + len(p.Data))
}

func (p *PublicKeyPayload) Load(scheme crypto.KemScheme) (crypto.KemPublicKey, error) {
	if p.key != nil {
		return p.key, nil
	}
	var err error
	p.key, err = scheme.UnmarshalBinaryPublicKey(p.Data)
	return p.key, err
}

func (p *PublicKeyPayload) Save(key crypto.KemPublicKey) error {
	if key == nil {
		return crypto.ErrKeyNil
	}
	p.key = key
	var err error
	p.Data, err = key.MarshalBinary()
	return err
}
