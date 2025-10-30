// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"github.com/1f349/handshake/crypto"
	intbyteutils "github.com/1f349/int-byte-utils"
	"hash"
	"io"
)

const PublicKeyDataPacketType = PacketType(6)

type PublicKeyDataPayload struct {
	Data []byte
	key  crypto.KemPublicKey
}

func (p *PublicKeyDataPayload) MarshalHashCalculator() hash.Hash {
	return nil
}

func (p *PublicKeyDataPayload) SetCompleteHash([]byte) {
}

func (p *PublicKeyDataPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := writeBuff(w, p.Data)
	return int64(m), err
}

func (p *PublicKeyDataPayload) ReadFrom(r io.Reader) (n int64, err error) {
	var m int
	m, err, p.Data = readBuff(r)
	return int64(m), err
}

func (p *PublicKeyDataPayload) Size() uint {
	return uint(intbyteutils.LenUintAsBytes(uint(len(p.Data))) + len(p.Data))
}

func (p *PublicKeyDataPayload) Load(scheme crypto.KemScheme) (crypto.KemPublicKey, error) {
	if p.key != nil {
		return p.key, nil
	}
	var err error
	p.key, err = scheme.UnmarshalBinaryPublicKey(p.Data)
	return p.key, err
}

func (p *PublicKeyDataPayload) Save(key crypto.KemPublicKey) error {
	if key == nil {
		return crypto.ErrKeyNil
	}
	p.key = key
	var err error
	p.Data, err = key.MarshalBinary()
	return err
}
