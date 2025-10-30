// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"slices"
	"testing"
	"time"
)

func TestPacketMarshal(t *testing.T) {
	sharedPacketMarshalTest(t, new(bytes.Buffer), 0)
}

func TestPacketMarshalFragmented(t *testing.T) {
	const MTU = 1280
	sharedPacketMarshalTest(t, newMTUTransport(MTU), MTU)
}

func TestPacketMarshalFragmentedSmallMTU(t *testing.T) {
	//const MTU = HeaderSizeForFragmentation + 1 //Not, this may be the minimum valid, but the maximum number of fragments is 255
	const MTU = 64
	sharedPacketMarshalTest(t, newMTUTransport(MTU), MTU)
}

func sharedPacketMarshalTest(t *testing.T, transport io.ReadWriter, mtu uint) {
	marshal := &PacketMarshaller{
		Conn: transport,
		MTU:  mtu,
	}
	connection := GetUUID()
	pt := MilliTime(time.Now())
	testOnePayload(t, "ConnectionRejectedPacketType_Valid", marshal, PacketHeader{ID: ConnectionRejectedPacketType, ConnectionUUID: connection, Time: pt}, ValidEmptyPayload, emptyPayloadChecker)
	testOnePayload(t, "PublicKeyRequestPacketType_Valid", marshal, PacketHeader{ID: PublicKeyRequestPacketType, ConnectionUUID: connection, Time: pt}, ValidEmptyPayload, emptyPayloadChecker)
	testOnePayload(t, "SignatureRequestPacketType_Valid", marshal, PacketHeader{ID: SignatureRequestPacketType, ConnectionUUID: connection, Time: pt}, ValidEmptyPayload, emptyPayloadChecker)
	testOnePayload(t, "SignaturePublicKeyRequestPacketType_Valid", marshal, PacketHeader{ID: SignaturePublicKeyRequestPacketType, ConnectionUUID: connection, Time: pt}, ValidEmptyPayload, emptyPayloadChecker)
	testOnePayload(t, "PublicKeyDataPacketType_Valid", marshal, PacketHeader{ID: PublicKeyDataPacketType, ConnectionUUID: connection, Time: pt}, GetValidPublicKeyPayload(), func(o PacketPayload, r PacketPayload) bool {
		k, err := r.(*PublicKeyDataPayload).Load(crypto.RSAKem4096Scheme)
		if err != nil || k == nil {
			return false
		}
		ko, err := o.(*PublicKeyDataPayload).Load(nil)
		if err != nil || ko == nil {
			return false
		}
		return ko.Equals(k)
	})
	testOnePayload(t, "PublicKeyDataPacketType_Invalid", marshal, PacketHeader{ID: PublicKeyDataPacketType, ConnectionUUID: connection, Time: pt}, GetInvalidPublicKeyPayload(), func(o PacketPayload, r PacketPayload) bool {
		k, err := r.(*PublicKeyDataPayload).Load(crypto.RSAKem4096Scheme)
		if err != nil && k == nil {
			return true
		}
		return false
	})
	testOnePayload(t, "SignedPacketPublicKeyPacketType_Valid", marshal, PacketHeader{ID: SignedPacketPublicKeyPacketType, ConnectionUUID: connection, Time: pt}, GetValidSignedPacketSigPublicKeyPayload(), func(o PacketPayload, r PacketPayload) bool {
		k, err := r.(*SignedPacketPublicKeyPayload).Load(crypto.RSASig4096Scheme)
		if err != nil || k == nil {
			return false
		}
		ko, err := o.(*SignedPacketPublicKeyPayload).Load(nil)
		if err != nil || ko == nil {
			return false
		}
		return ko.Equals(k)
	})
	testOnePayload(t, "SignedPacketPublicKeyPacketType_Invalid", marshal, PacketHeader{ID: SignedPacketPublicKeyPacketType, ConnectionUUID: connection, Time: pt}, GetInvalidSignedPacketSigPublicKeyPayload(), func(o PacketPayload, r PacketPayload) bool {
		k, err := r.(*SignedPacketPublicKeyPayload).Load(crypto.RSASig4096Scheme)
		if err != nil && k == nil {
			return true
		}
		return false
	})
	testOnePayload(t, "PublicKeySignedPacketType_Valid", marshal, PacketHeader{ID: PublicKeySignedPacketType, ConnectionUUID: connection, Time: pt}, GetValidPublicKeySignedPacketPayload(), func(o PacketPayload, r PacketPayload) bool {
		if !slices.Equal(validPublicKeySignedPacketPayloadSigPubKeyHash, r.(*PublicKeySignedPacketPayload).SigPubKeyHash) {
			return false
		}
		sigData, err := r.(*PublicKeySignedPacketPayload).Load(validPublicKeySignedPacketPayloadKemPubKey)
		if err != nil || sigData.Signature == nil {
			return false
		}
		return sigData.Verify(sha256.New(), validPublicKeySignedPacketPayloadSigPubKey)
	})
	testOnePayload(t, "PublicKeySignedPacketType_Invalid", marshal, PacketHeader{ID: PublicKeySignedPacketType, ConnectionUUID: connection, Time: pt}, GetInvalidPublicKeySignedPacketPayload(), func(o PacketPayload, r PacketPayload) bool {
		if !slices.Equal([]byte{0, 1, 2, 3}, r.(*PublicKeySignedPacketPayload).SigPubKeyHash) {
			return false
		}
		sigData, err := r.(*PublicKeySignedPacketPayload).Load(validPublicKeySignedPacketPayloadKemPubKey)
		return err != nil && sigData.Signature == nil
	})
	//TODO: Tests
	testOnePayload(t, "FinalProofPacketType_Valid", marshal, PacketHeader{ID: FinalProofPacketType, ConnectionUUID: connection, Time: pt}, ValidFinalProofPayload, func(o PacketPayload, r PacketPayload) bool {
		return slices.Equal(o.(*FinalProofPayload).ProofHMAC, r.(*FinalProofPayload).ProofHMAC)
	})
	testOnePayload(t, "FinalProofPacketType_Invalid", marshal, PacketHeader{ID: FinalProofPacketType, ConnectionUUID: connection, Time: pt}, InvalidFinalProofPayload, func(o PacketPayload, r PacketPayload) bool {
		return slices.Equal(o.(*FinalProofPayload).ProofHMAC, r.(*FinalProofPayload).ProofHMAC) && len(r.(*FinalProofPayload).ProofHMAC) == 0
	})
}

func emptyPayloadChecker(PacketPayload, PacketPayload) bool {
	return true
}

func testOnePayload(t *testing.T, name string, marshal *PacketMarshaller, header PacketHeader, payload PacketPayload, payloadChecker func(o PacketPayload, r PacketPayload) bool) {
	t.Run(name, func(t *testing.T) {
		err := marshal.Marshal(header, payload)
		assert.NoError(t, err)
		var rHeader *PacketHeader
		var rPayload PacketPayload
		err = ErrFragmentReceived
		for errors.Is(err, ErrFragmentReceived) {
			rHeader, rPayload, err = marshal.Unmarshal()
		}
		assert.NotNil(t, rHeader)
		assert.NoError(t, err)
		assert.NotNil(t, rPayload)
		if rHeader != nil {
			assert.True(t, header.Equals(*rHeader))
		}
		if rPayload != nil {
			assert.Equal(t, payload.Size(), rPayload.Size())
			assert.True(t, payloadChecker(payload, rPayload))
		}
	})
}

func TestMTUWriterReader(t *testing.T) {
	a1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	a2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	buff := new(bytes.Buffer)
	writer := &mtuWriter{mtu: 8, target: buff}
	n, err := writer.Write(a1)
	assert.NoError(t, err)
	assert.Equal(t, 8, n)

	n, err = writer.Write(a2)
	assert.Error(t, err)
	assert.Equal(t, ErrTooMuchData, err)
	assert.NotEqual(t, 8, n)
	assert.Equal(t, 0, n)

	n, err = writer.Write(a1)
	assert.NoError(t, err)
	assert.Equal(t, 8, n)

	n, err = writer.Write([]byte{1, 2, 3, 4})
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, 20, buff.Len())

	reader := &mtuReader{mtuBuff: make([]byte, 8), target: buff}

	data := make([]byte, 8)
	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.True(t, slices.Equal(a1, data))
	data = data[:6]

	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.True(t, slices.Equal(a1[:6], data))
	data = make([]byte, 7)

	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.NotEqual(t, 8, n)
	assert.Equal(t, 4, n)
	assert.True(t, slices.Equal([]byte{1, 2, 3, 4, 0, 0, 0}, data))
}

func TestFixedTransport(t *testing.T) {
	const mtu = 10
	transport := &fixedTransport{queue: make([][]byte, 0)}
	writer := &mtuWriter{mtu: mtu, target: transport}
	reader := &mtuReader{mtuBuff: make([]byte, mtu), target: transport}
	a1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	a2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	a3 := []byte{1, 2, 3, 4}

	n, err := writer.Write(a1)
	assert.NoError(t, err)
	assert.Equal(t, mtu, n)

	n, err = writer.Write(a2)
	assert.Error(t, err)
	assert.NotEqual(t, mtu, n)
	assert.Equal(t, 0, n)
	assert.Equal(t, ErrTooMuchData, err)

	n, err = writer.Write(a1)
	assert.NoError(t, err)
	assert.Equal(t, mtu, n)

	n, err = writer.Write(a3)
	assert.NoError(t, err)
	assert.Equal(t, 4, n)

	data := make([]byte, mtu)
	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, mtu, n)
	assert.True(t, slices.Equal(a1, data))
	data = data[:6]

	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.True(t, slices.Equal(a1[:6], data))

	n, err = writer.Write(a3)
	assert.NoError(t, err)
	assert.Equal(t, 4, n)

	data = make([]byte, 7)
	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.NotEqual(t, 7, n)
	assert.Equal(t, 4, n)
	assert.True(t, slices.Equal(a3, data[:4]))

	data = data[:4]
	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.True(t, slices.Equal(a3, data))

	n, err = reader.Read(data)
	assert.Error(t, err)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
}

func newMTUTransport(mtu int) *mtuTransport {
	transport := &fixedTransport{queue: make([][]byte, 0)}
	return &mtuTransport{
		reader: &mtuReader{
			mtuBuff: make([]byte, mtu),
			target:  transport,
		},
		writer: &mtuWriter{
			mtu:    mtu,
			target: transport,
		},
	}
}

type mtuTransport struct {
	reader *mtuReader
	writer *mtuWriter
}

func (m *mtuTransport) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m *mtuTransport) Write(p []byte) (n int, err error) {
	return m.writer.Write(p)
}

type mtuReader struct {
	mtuBuff []byte
	target  io.Reader
}

func (m *mtuReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err = m.target.Read(m.mtuBuff)
	n = copy(p, m.mtuBuff[:min(n, len(p))])
	return
}

type mtuWriter struct {
	mtu    int
	target io.Writer
}

func (m *mtuWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > m.mtu {
		return 0, ErrTooMuchData
	}
	return m.target.Write(p)
}

type fixedTransport struct {
	queue [][]byte
}

func (m *fixedTransport) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(m.queue) == 0 {
		return 0, io.EOF
	}
	n = copy(p, m.queue[0])
	m.queue = m.queue[1:]
	return
}

func (m *fixedTransport) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	cpy := make([]byte, len(p))
	n = copy(cpy, p)
	m.queue = append(m.queue, cpy)
	return
}
