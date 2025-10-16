// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"github.com/1f349/handshake/crypto"
	intbyteutils "github.com/1f349/int-byte-utils"
	"io"
)

const SignedPacketSigPublicKeyPacketType = PacketType(10)

type SignedPacketSigPublicKeyPayload struct {
	Data []byte
	key  crypto.SigPublicKey
}

func (p *SignedPacketSigPublicKeyPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := writeBuff(w, p.Data)
	return int64(m), err
}

func (p *SignedPacketSigPublicKeyPayload) ReadFrom(r io.Reader) (n int64, err error) {
	var m int
	m, err, p.Data = readBuff(r)
	return int64(m), err
}

func (p *SignedPacketSigPublicKeyPayload) Size() uint {
	return uint(intbyteutils.LenUintAsBytes(uint(len(p.Data))) + len(p.Data))
}

func (p *SignedPacketSigPublicKeyPayload) Load(scheme crypto.SigScheme) (crypto.SigPublicKey, error) {
	if p.key != nil {
		return p.key, nil
	}
	var err error
	p.key, err = scheme.UnmarshalBinaryPublicKey(p.Data)
	return p.key, err
}

func (p *SignedPacketSigPublicKeyPayload) Save(key crypto.SigPublicKey) error {
	if key == nil {
		return crypto.ErrKeyNil
	}
	p.key = key
	var err error
	p.Data, err = key.MarshalBinary()
	return err
}
