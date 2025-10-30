// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	intbyteutils "github.com/1f349/int-byte-utils"
	"hash"
	"io"
)

const FinalProofPacketType = PacketType(4)

type FinalProofPayload struct {
	ProofHMAC []byte
}

func (f *FinalProofPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := writeBuff(w, f.ProofHMAC)
	return int64(m), err
}

func (f *FinalProofPayload) ReadFrom(r io.Reader) (n int64, err error) {
	var m int
	m, err, f.ProofHMAC = readBuff(r)
	return int64(m), err
}

func (f *FinalProofPayload) Size() uint {
	return uint(intbyteutils.LenUintAsBytes(uint(len(f.ProofHMAC))) + len(f.ProofHMAC))
}

func (f *FinalProofPayload) MarshalHashCalculator() hash.Hash {
	return nil
}

func (f *FinalProofPayload) SetCompleteHash(bytes []byte) {
}
