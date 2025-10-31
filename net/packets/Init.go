// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"errors"
	"github.com/1f349/handshake/crypto"
	intbyteutils "github.com/1f349/int-byte-utils"
	"hash"
	"io"
)

const InitPacketType = PacketType(2)

// ErrNoEncapsulation for no encapsulation data (Protocol 2A)
var ErrNoEncapsulation = errors.New("no encapsulation")

type InitPayload struct {
	encapsulation []byte
	// PublicKeyHash hash of the local crypto.KemPublicKey
	PublicKeyHash []byte
	// PacketHash contains the hash of the packet when sent by a PacketMarshaller with its header information using PacketHasher
	PacketHash   []byte
	PacketHasher hash.Hash
}

func (i *InitPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := writeBuff(w, i.encapsulation)
	if err != nil {
		return int64(m), err
	}
	l, err := writeBuff(w, i.PublicKeyHash)
	return int64(m + l), err
}

func (i *InitPayload) ReadFrom(r io.Reader) (n int64, err error) {
	var m int
	m, err, i.encapsulation = readBuff(r)
	if err != nil {
		return int64(m), err
	}
	var l int
	l, err, i.PublicKeyHash = readBuff(r)
	return int64(m + l), err
}

func (i *InitPayload) Size() uint {
	return uint(intbyteutils.LenUintAsBytes(uint(len(i.encapsulation))) + len(i.encapsulation) + intbyteutils.LenUintAsBytes(uint(len(i.PublicKeyHash))) + len(i.PublicKeyHash))
}

func (i *InitPayload) MarshalHashCalculator() hash.Hash {
	return i.PacketHasher
}

func (i *InitPayload) SetCompleteHash(bytes []byte) {
	i.PacketHash = bytes
}

// Encapsulate can have k nil to clear the stored encapsulation, will still return crypto.ErrKeyNil in this scenario
func (i *InitPayload) Encapsulate(k crypto.KemPublicKey) (secret []byte, err error) {
	if k == nil {
		i.encapsulation = nil
		return nil, crypto.ErrKeyNil
	}
	i.encapsulation, secret, err = k.Scheme().Encapsulate(k)
	return
}

func (i *InitPayload) Decapsulate(k crypto.KemPrivateKey) (secret []byte, err error) {
	if k == nil {
		return nil, crypto.ErrKeyNil
	}
	if len(i.encapsulation) < 1 {
		return nil, ErrNoEncapsulation
	}
	secret, err = k.Scheme().Decapsulate(k, i.encapsulation)
	return
}
