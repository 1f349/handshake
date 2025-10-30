// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"github.com/1f349/handshake/crypto"
	intbyteutils "github.com/1f349/int-byte-utils"
	"hash"
	"io"
)

const InitProofPacketType = PacketType(3)

type InitProofPayload struct {
	encapsulation []byte
	ProofHMAC     []byte
	PacketHash    []byte
	PacketHasher  hash.Hash
}

func (i *InitProofPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := writeBuff(w, i.encapsulation)
	if err != nil {
		return int64(m), err
	}
	l, err := writeBuff(w, i.ProofHMAC)
	return int64(m + l), err
}

func (i *InitProofPayload) ReadFrom(r io.Reader) (n int64, err error) {
	var m int
	m, err, i.encapsulation = readBuff(r)
	if err != nil {
		return int64(m), err
	}
	var l int
	l, err, i.ProofHMAC = readBuff(r)
	return int64(m + l), err
}

func (i *InitProofPayload) Size() uint {
	return uint(intbyteutils.LenUintAsBytes(uint(len(i.encapsulation))) + len(i.encapsulation) + intbyteutils.LenUintAsBytes(uint(len(i.ProofHMAC))) + len(i.ProofHMAC))
}

func (i *InitProofPayload) MarshalHashCalculator() hash.Hash {
	return i.PacketHasher
}

func (i *InitProofPayload) SetCompleteHash(bytes []byte) {
	i.PacketHash = bytes
}

// Encapsulate can have k nil to clear the stored encapsulation, will still return crypto.ErrKeyNil in this scenario
func (i *InitProofPayload) Encapsulate(k crypto.KemPublicKey) (secret []byte, err error) {
	if k == nil {
		i.encapsulation = nil
		return nil, crypto.ErrKeyNil
	}
	i.encapsulation, secret, err = k.Scheme().Encapsulate(k)
	return
}

func (i *InitProofPayload) Decapsulate(k crypto.KemPrivateKey) (secret []byte, err error) {
	if k == nil {
		return nil, crypto.ErrKeyNil
	}
	if len(i.encapsulation) < 1 {
		return nil, ErrNoEncapsulation
	}
	secret, err = k.Scheme().Decapsulate(k, i.encapsulation)
	return
}
