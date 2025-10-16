// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"hash"
	"io"
)

const ConnectionRejectedPacketType = PacketType(1)
const PublicKeyRequestPacketType = PacketType(5)
const SignatureRequestPacketType = PacketType(7)
const SignaturePublicKeyRequestPacketType = PacketType(9)

// EmptyPayload Provides a payload for ConnectionRejectedPacketType, PublicKeyRequestPacketType, SignatureRequestPacketType and SignaturePublicKeyRequestPacketType
type EmptyPayload struct {
}

func (e *EmptyPayload) MarshalHashCalculator() hash.Hash {
	return nil
}

func (e *EmptyPayload) SetCompleteHash([]byte) {
}

func (e *EmptyPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := w.Write(nil)
	return int64(m), err
}

func (e *EmptyPayload) ReadFrom(r io.Reader) (n int64, err error) {
	m, err := r.Read(nil)
	return int64(m), err
}

func (e *EmptyPayload) Size() uint {
	return 0
}
