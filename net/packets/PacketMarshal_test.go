// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"slices"
	"testing"
	"time"
)

var marshalLocalKey crypto.KemPrivateKey
var marshalRemoteKey crypto.KemPrivateKey
var MarshalHasher = sha256.New()
var MarshalHMACBase = sha256.New

func GetMarshalLocalKey() crypto.KemPrivateKey {
	if marshalLocalKey == nil {
		scheme := crypto.RSAKem4096Scheme
		var err error
		_, marshalLocalKey, err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
	}
	return marshalLocalKey
}

func GetMarshalRemoteKey() crypto.KemPrivateKey {
	if marshalRemoteKey == nil {
		scheme := crypto.RSAKem4096Scheme
		var err error
		_, marshalRemoteKey, err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
	}
	return marshalRemoteKey
}

func TestPacketMarshal(t *testing.T) {
	sharedPacketMarshalTest(t, new(bytes.Buffer), 0)
}

func TestPacketMarshalFragmented(t *testing.T) {
	const MTU = 1280
	sharedPacketMarshalTest(t, newMTUTransport(MTU), MTU)
}

func TestPacketMarshalFragmentedSmallMTU(t *testing.T) {
	//const MTU = HeaderSizeForFragmentation + 1 //Note, this may be the minimum valid, but the maximum number of fragments is 255
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

	testOnePayload(t, "InitPacketType_Valid2", marshal, PacketHeader{ID: InitPacketType, ConnectionUUID: connection, Time: pt}, GetInitPayload(initTestValid2), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitPayload).Decapsulate(GetInitKey(initTestValid2))
		assert.NoError(t, err)
		assert.Equal(t, InitSecrets[initTestValid2], cs)
		return slices.Equal(o.(*InitPayload).PublicKeyHash, r.(*InitPayload).PublicKeyHash)
	})
	testOnePayload(t, "InitPacketType_Valid2B", marshal, PacketHeader{ID: InitPacketType, ConnectionUUID: connection, Time: pt}, GetInitPayload(initTestValid2B), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitPayload).Decapsulate(GetInitKey(initTestValid2B))
		assert.NoError(t, err)
		assert.Equal(t, InitSecrets[initTestValid2B], cs)
		return slices.Equal(o.(*InitPayload).PublicKeyHash, r.(*InitPayload).PublicKeyHash) && len(r.(*InitPayload).PublicKeyHash) < 1
	})
	testOnePayload(t, "InitPacketType_Valid2A", marshal, PacketHeader{ID: InitPacketType, ConnectionUUID: connection, Time: pt}, GetInitPayload(initTestValid2A), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitPayload).Decapsulate(GetInitKey(initTestValid2A))
		assert.Error(t, err)
		assert.Equal(t, ErrNoEncapsulation, err)
		assert.Nil(t, cs)
		return slices.Equal(o.(*InitPayload).PublicKeyHash, r.(*InitPayload).PublicKeyHash)
	})
	testOnePayload(t, "InitPacketType_Valid2AB", marshal, PacketHeader{ID: InitPacketType, ConnectionUUID: connection, Time: pt}, GetInitPayload(initTestValid2AB), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitPayload).Decapsulate(GetInitKey(initTestValid2AB))
		assert.Error(t, err)
		assert.Equal(t, ErrNoEncapsulation, err)
		assert.Nil(t, cs)
		return slices.Equal(o.(*InitPayload).PublicKeyHash, r.(*InitPayload).PublicKeyHash) && len(r.(*InitPayload).PublicKeyHash) < 1
	})
	testOnePayload(t, "InitPacketType_Invalid2", marshal, PacketHeader{ID: InitPacketType, ConnectionUUID: connection, Time: pt}, GetInitPayload(initTestInvalid2), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitPayload).Decapsulate(GetInitKey(initTestValid2))
		assert.NoError(t, err)
		assert.NotEqual(t, InitSecrets[initTestInvalid2], cs)
		return slices.Equal(o.(*InitPayload).PublicKeyHash, r.(*InitPayload).PublicKeyHash)
	})
	testOnePayload(t, "InitPacketType_Invalid2B", marshal, PacketHeader{ID: InitPacketType, ConnectionUUID: connection, Time: pt}, GetInitPayload(initTestInvalid2B), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitPayload).Decapsulate(GetInitKey(initTestValid2B))
		assert.NoError(t, err)
		assert.NotEqual(t, InitSecrets[initTestInvalid2B], cs)
		return slices.Equal(o.(*InitPayload).PublicKeyHash, r.(*InitPayload).PublicKeyHash) && len(r.(*InitPayload).PublicKeyHash) < 1
	})

	testOnePayload(t, "InitProofPacketType_Valid", marshal, PacketHeader{ID: InitProofPacketType, ConnectionUUID: connection, Time: pt}, GetInitProofPayload(initProofTestValid), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitProofPayload).Decapsulate(GetInitProofKey(initProofTestValid))
		assert.NoError(t, err)
		assert.Equal(t, InitProofSecrets[initProofTestValid], cs)
		return slices.Equal(o.(*InitProofPayload).ProofHMAC, r.(*InitProofPayload).ProofHMAC)
	})
	testOnePayload(t, "InitProofPacketType_InvalidEncapsulation", marshal, PacketHeader{ID: InitProofPacketType, ConnectionUUID: connection, Time: pt}, GetInitProofPayload(initProofTestInvalidEncapsulation), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitProofPayload).Decapsulate(GetInitProofKey(initProofTestValid))
		assert.NoError(t, err)
		assert.NotEqual(t, InitProofSecrets[initProofTestInvalidEncapsulation], cs)
		return slices.Equal(o.(*InitProofPayload).ProofHMAC, r.(*InitProofPayload).ProofHMAC)
	})
	testOnePayload(t, "InitProofPacketType_InvalidHMAC", marshal, PacketHeader{ID: InitProofPacketType, ConnectionUUID: connection, Time: pt}, GetInitProofPayload(initProofTestInvalidHMAC), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitProofPayload).Decapsulate(GetInitProofKey(initProofTestInvalidHMAC))
		assert.NoError(t, err)
		assert.Equal(t, InitProofSecrets[initProofTestInvalidHMAC], cs)
		return slices.Equal(o.(*InitProofPayload).ProofHMAC, r.(*InitProofPayload).ProofHMAC) && len(r.(*InitProofPayload).ProofHMAC) == 0
	})
	testOnePayload(t, "InitProofPacketType_Invalid", marshal, PacketHeader{ID: InitProofPacketType, ConnectionUUID: connection, Time: pt}, GetInitProofPayload(initProofTestInvalid), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitProofPayload).Decapsulate(GetInitProofKey(initProofTestValid))
		assert.NoError(t, err)
		assert.NotEqual(t, InitProofSecrets[initProofTestInvalid], cs)
		return slices.Equal(o.(*InitProofPayload).ProofHMAC, r.(*InitProofPayload).ProofHMAC) && len(r.(*InitProofPayload).ProofHMAC) == 0
	})
	testOnePayload(t, "InitProofPacketType_InvalidEmptyEncapsulation", marshal, PacketHeader{ID: InitProofPacketType, ConnectionUUID: connection, Time: pt}, GetInitProofPayload(initProofTestEmptyEncapsulationInvalid), func(o PacketPayload, r PacketPayload) bool {
		cs, err := r.(*InitProofPayload).Decapsulate(GetInitProofKey(initProofTestValid))
		assert.Error(t, err)
		assert.Equal(t, ErrNoEncapsulation, err)
		assert.Nil(t, cs)
		return slices.Equal(o.(*InitProofPayload).ProofHMAC, r.(*InitProofPayload).ProofHMAC) && len(r.(*InitProofPayload).ProofHMAC) == 0
	})

	testOnePayload(t, "FinalProofPacketType_Valid", marshal, PacketHeader{ID: FinalProofPacketType, ConnectionUUID: connection, Time: pt}, ValidFinalProofPayload, func(o PacketPayload, r PacketPayload) bool {
		return slices.Equal(o.(*FinalProofPayload).ProofHMAC, r.(*FinalProofPayload).ProofHMAC)
	})
	testOnePayload(t, "FinalProofPacketType_Invalid", marshal, PacketHeader{ID: FinalProofPacketType, ConnectionUUID: connection, Time: pt}, InvalidFinalProofPayload, func(o PacketPayload, r PacketPayload) bool {
		return slices.Equal(o.(*FinalProofPayload).ProofHMAC, r.(*FinalProofPayload).ProofHMAC) && len(r.(*FinalProofPayload).ProofHMAC) == 0
	})

	t.Run("MainFlow", func(t *testing.T) {
		lHash := BinaryMarshalHash(GetMarshalLocalKey().Public(), MarshalHasher)

		initP := &InitPayload{PublicKeyHash: lHash}
		ss1Local, err := initP.Encapsulate(GetMarshalRemoteKey().Public())
		assert.NoError(t, err)
		assert.NotNil(t, ss1Local)
		initP.PacketHasher = hmac.New(MarshalHMACBase, ss1Local)
		err = marshal.Marshal(PacketHeader{ID: InitPacketType, ConnectionUUID: connection, Time: pt.Add(time.Second)}, initP)
		assert.NoError(t, err)
		rHeader, rPayload := readOnePayload(t, marshal)
		assert.True(t, pt.Add(time.Second).Equal(rHeader.Time))
		ss1Remote, err := rPayload.(*InitPayload).Decapsulate(GetMarshalRemoteKey())
		assert.NoError(t, err)
		assert.Equal(t, ss1Local, ss1Remote)
		assert.Equal(t, lHash, rPayload.(*InitPayload).PublicKeyHash)

		initProofP := &InitProofPayload{ProofHMAC: PacketDataHash(*rHeader, rPayload, hmac.New(MarshalHMACBase, ss1Remote))}
		ss2Remote, err := initProofP.Encapsulate(GetMarshalLocalKey().Public())
		assert.NoError(t, err)
		assert.NotNil(t, ss2Remote)
		initProofP.PacketHasher = hmac.New(MarshalHMACBase, ss2Remote)
		err = marshal.Marshal(PacketHeader{ID: InitProofPacketType, ConnectionUUID: connection, Time: pt.Add(time.Minute)}, initProofP)
		assert.NoError(t, err)
		rHeader, rPayload = readOnePayload(t, marshal)
		assert.True(t, pt.Add(time.Minute).Equal(rHeader.Time))
		ss2Local, err := rPayload.(*InitProofPayload).Decapsulate(GetMarshalLocalKey())
		assert.NoError(t, err)
		assert.Equal(t, ss2Local, ss2Remote)
		assert.True(t, subtle.ConstantTimeCompare(initP.PacketHash, rPayload.(*InitProofPayload).ProofHMAC) == 1)

		finalProofP := &FinalProofPayload{ProofHMAC: PacketDataHash(*rHeader, rPayload, hmac.New(MarshalHMACBase, ss2Local))}
		err = marshal.Marshal(PacketHeader{ID: FinalProofPacketType, ConnectionUUID: connection, Time: pt.Add(time.Minute * 2)}, finalProofP)
		assert.NoError(t, err)
		rHeader, rPayload = readOnePayload(t, marshal)
		assert.True(t, pt.Add(time.Minute*2).Equal(rHeader.Time))
		assert.True(t, subtle.ConstantTimeCompare(initProofP.PacketHash, rPayload.(*FinalProofPayload).ProofHMAC) == 1)
	})
}

func emptyPayloadChecker(PacketPayload, PacketPayload) bool {
	return true
}

func readOnePayload(t *testing.T, marshal *PacketMarshaller) (*PacketHeader, PacketPayload) {
	var rHeader *PacketHeader
	var rPayload PacketPayload
	err := ErrFragmentReceived
	for errors.Is(err, ErrFragmentReceived) {
		rHeader, rPayload, err = marshal.Unmarshal()
	}
	assert.NotNil(t, rHeader)
	assert.NoError(t, err)
	assert.NotNil(t, rPayload)
	return rHeader, rPayload
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
