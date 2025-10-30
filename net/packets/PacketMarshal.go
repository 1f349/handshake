// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"errors"
	"hash"
	"io"
	"math"
	"sync"
)

var ErrFragmentReceived = errors.New("fragment received")
var ErrInvalidPacketID = errors.New("invalid packet id")
var ErrFragmentIndexOutOfRange = errors.New("fragment index out of range")
var ErrTooManyFragments = errors.New("too many fragments")

type PacketPayload interface {
	io.WriterTo
	io.ReaderFrom
	Size() uint
	// MarshalHashCalculator is nil when not supported, provides a way of hashing the packet header and body while marshalling
	MarshalHashCalculator() hash.Hash
	// SetCompleteHash is called once marshaling is complete and MarshalHashCalculator returned a valid hash instance
	SetCompleteHash([]byte)
}

type PacketMarshaller struct {
	Conn io.ReadWriter
	// MTU Conn, maximum transmission unit, makes sure packets get fragmented if needed and enables buffer support when > 0; if 0, there is no length limit and no fragmentation
	MTU                    uint
	fragments              [][]byte
	fragmentedPacketHeader PacketHeader
	fragmentMutex          sync.Mutex
}

func (p *PacketMarshaller) Unmarshal() (packetHeader *PacketHeader, packetPayload PacketPayload, err error) {
	packetHeader = &PacketHeader{}
	var localConn io.ReadWriter
	if p.MTU > 0 {
		packetData := make([]byte, p.MTU)
		_, err = p.Conn.Read(packetData)
		if err != nil && err != io.EOF {
			return packetHeader, nil, err
		}
		localConn = bytes.NewBuffer(packetData)
	} else {
		localConn = p.Conn
	}
	_, err = packetHeader.ReadFrom(localConn)
	if err != nil {
		return packetHeader, nil, err
	}
	if packetHeader.IsFragment() {
		bts := make([]byte, packetHeader.fragmentSize)
		_, err = io.ReadFull(localConn, bts)
		if err != nil {
			return packetHeader, nil, err
		}
		return p.processFragment(bts, *packetHeader)
	} else {
		return p.unmarshal(*packetHeader, localConn)
	}
}

func (p *PacketMarshaller) unmarshal(header PacketHeader, conn io.Reader) (*PacketHeader, PacketPayload, error) {
	var pyld PacketPayload
	switch header.ID {
	case ConnectionRejectedPacketType, PublicKeyRequestPacketType, SignatureRequestPacketType, SignaturePublicKeyRequestPacketType:
		pyld = &EmptyPayload{}
	case PublicKeyDataPacketType:
		pyld = &PublicKeyDataPayload{}
	case SignedPacketPublicKeyPacketType:
		pyld = &SignedPacketPublicKeyPayload{}
	case PublicKeySignedPacketType:
		pyld = &PublicKeySignedPacketPayload{}
	default:
		return header.Clone(), nil, ErrInvalidPacketID
	}
	_, err := pyld.ReadFrom(conn)
	if err != nil {
		return header.Clone(), nil, err
	}
	return header.Clone(), pyld, nil
}

func (p *PacketMarshaller) Marshal(packetHeader PacketHeader, payload PacketPayload) error {
	if p.MTU > 0 {
		if HeaderSizeForFragmentation >= p.MTU {
			return ErrMTUTooSmall
		} else {
			sz := payload.Size()
			var pw *packetFragmentWriter
			pHasher := payload.MarshalHashCalculator()
			if pHasher != nil {
				pHasher.Reset()
				_, err := packetHeader.Clone().WriteTo(pHasher)
				if err != nil {
					return err
				}
			}
			if sz+HeaderSize <= p.MTU {
				pw = &packetFragmentWriter{target: p.Conn, header: *packetHeader.Clone(), mtu: p.MTU}
			} else {
				fc := sz / (p.MTU - HeaderSizeForFragmentation)
				if sz%(p.MTU-HeaderSizeForFragmentation) > 0 {
					fc++
				}
				if fc > math.MaxUint8 {
					return ErrTooManyFragments
				}
				pw = &packetFragmentWriter{target: p.Conn, header: *packetHeader.CloneAsFragment(0, byte(fc), uint16(p.MTU-HeaderSizeForFragmentation)), mtu: p.MTU, fragmentWrite: true}
			}
			var pwa io.Writer
			if pHasher == nil {
				pwa = pw
			} else {
				pwa = io.MultiWriter(pw, pHasher)
			}
			_, err := payload.WriteTo(pwa)
			if err != nil {
				return err
			}
			if sz == 0 { // Dummy write if zero payload to force packetFragmentWriter init
				_, _ = pw.Write(nil)
			}
			err = pw.Flush()
			if err != nil {
				return err
			}
			if pHasher != nil {
				payload.SetCompleteHash(pHasher.Sum(nil))
			}
		}
	} else {
		var pwa io.Writer
		pHasher := payload.MarshalHashCalculator()
		if pHasher == nil {
			pwa = p.Conn
		} else {
			pHasher.Reset()
			pwa = io.MultiWriter(p.Conn, pHasher)
		}
		_, err := packetHeader.Clone().WriteTo(pwa)
		if err != nil {
			return err
		}
		_, err = payload.WriteTo(pwa)
		if err != nil {
			return err
		}
		if pHasher != nil {
			payload.SetCompleteHash(pHasher.Sum(nil))
		}
	}
	return nil
}

func (p *PacketMarshaller) processFragment(f []byte, header PacketHeader) (*PacketHeader, PacketPayload, error) {
	p.fragmentMutex.Lock()
	defer p.fragmentMutex.Unlock()
	if len(p.fragments) != int(header.fragmentCount) || !header.Equals(p.fragmentedPacketHeader) {
		p.fragments = make([][]byte, header.fragmentCount)
		p.fragmentedPacketHeader.Set(header)
	}
	if int(header.fragmentIndex) >= len(p.fragments) {
		return &header, nil, ErrFragmentIndexOutOfRange
	}
	p.fragments[header.fragmentIndex] = f
	buff := new(bytes.Buffer)
	for _, f := range p.fragments {
		if f == nil {
			return &header, nil, ErrFragmentReceived
		} else {
			buff.Write(f)
		}
	}
	defer p.clearFragmentCache()
	return p.unmarshal(p.fragmentedPacketHeader, buff)
}

func (p *PacketMarshaller) clearFragmentCache() {
	p.fragments = nil
	p.fragmentedPacketHeader.Clear()
}

func (p *PacketMarshaller) ClearFragmentCache() {
	p.fragmentMutex.Lock()
	defer p.fragmentMutex.Unlock()
	p.clearFragmentCache()
}
