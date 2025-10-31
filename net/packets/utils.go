// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"crypto/rand"
	"encoding"
	"errors"
	intbyteutils "github.com/1f349/int-byte-utils"
	"hash"
	"io"
	"time"
)

var ErrMTUTooSmall = errors.New("MTU too small")
var ErrTooMuchData = errors.New("too much data")
var ErrNoPacketToFlush = errors.New("no packet to flush")

type packetFragmentWriter struct {
	target        io.Writer
	mtu           uint
	header        PacketHeader
	fragmentWrite bool
	data          []byte
	index         uint
}

func (pw *packetFragmentWriter) Write(p []byte) (n int, err error) {
	if len(pw.data) == 0 {
		if pw.fragmentWrite {
			if HeaderSizeForFragmentation >= pw.mtu {
				return 0, ErrMTUTooSmall
			} else {
				pw.header.fragmentSize = uint16(pw.mtu - HeaderSizeForFragmentation)
				pw.index = HeaderSizeForFragmentation
			}
		} else {
			if HeaderSize >= pw.mtu {
				return 0, ErrMTUTooSmall
			} else {
				pw.header.fragmentSize = uint16(pw.mtu - HeaderSize)
				pw.index = HeaderSize
			}
		}
		pw.header.fragmentIndex = 0
		pw.data = make([]byte, pw.mtu)
	}
	pIdx := uint(0)
	for pIdx < uint(len(p)) {
		eCount := min(uint(len(p))-pIdx, uint(len(pw.data))-pw.index)
		n += copy(pw.data[pw.index:pw.index+eCount], p[pIdx:pIdx+eCount])
		pIdx += eCount
		pw.index += eCount
		if pw.index == uint(len(pw.data)) {
			if pw.fragmentWrite {
				var lN int64
				lN, err = pw.header.WriteTo(&overwriter{buff: pw.data})
				if err != nil {
					return
				}
				if lN != HeaderSizeForFragmentation {
					err = io.EOF
					return
				}
				_, err = pw.target.Write(pw.data)
				pw.header.fragmentIndex += 1
				pw.index = HeaderSizeForFragmentation
			} else {
				if pIdx != uint(len(p)) {
					err = ErrTooMuchData
					return
				} else {
					err = pw.Flush()
				}
			}
		}
	}
	return
}

func (pw *packetFragmentWriter) Flush() error {
	if len(pw.data) == 0 {
		return ErrNoPacketToFlush
	}
	var n int
	var err error
	if (pw.fragmentWrite && pw.index > HeaderSizeForFragmentation) || !pw.fragmentWrite {
		pw.header.fragmentSize = uint16(pw.index - HeaderSizeForFragmentation)
		var lN int64
		lN, err = pw.header.WriteTo(&overwriter{buff: pw.data})
		if err != nil {
			return err
		}
		if (pw.fragmentWrite && lN != HeaderSizeForFragmentation) || (!pw.fragmentWrite && lN != HeaderSize) {
			return io.EOF
		}
		n, err = pw.target.Write(pw.data[:pw.index])
	}
	defer func() {
		pw.index = 0
		pw.data = nil
	}()
	if n < 0 || (uint(n) != pw.index && ((pw.fragmentWrite && pw.index > HeaderSizeForFragmentation) || !pw.fragmentWrite)) {
		return io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	return nil
}

type overwriter struct {
	buff  []byte
	index int
}

func (o *overwriter) Write(p []byte) (n int, err error) {
	if o.index+len(p) > len(o.buff) {
		return copy(o.buff[o.index:], p), ErrTooMuchData
	}
	o.index += copy(o.buff[o.index:o.index+len(p)], p)
	return len(p), nil
}

func readBuff(r io.Reader) (n int, err error, buff []byte) {
	n, err, l := intbyteutils.ReadUintFromBytes(r)
	if err != nil {
		return
	}
	buff = make([]byte, l)
	m, err := io.ReadFull(r, buff)
	n += m
	if m < 0 || uint(m) != l {
		err = io.ErrUnexpectedEOF
	}
	return
}

func writeBuff(w io.Writer, buff []byte) (n int, err error) {
	n, err = intbyteutils.WriteUintAsBytes(uint(len(buff)), w)
	if err != nil {
		return
	}
	m, err := w.Write(buff)
	n += m
	if m < 0 || m != len(buff) {
		err = io.ErrShortWrite
	}
	return
}

func GetUUID() [16]byte {
	uuid := [16]byte{}
	_, _ = rand.Read(uuid[:])
	return uuid
}

func MilliTime(t time.Time) time.Time {
	return time.UnixMilli(t.UnixMilli())
}

func PacketDataHash(packetHeader PacketHeader, payload PacketPayload, h hash.Hash) []byte {
	if payload == nil || h == nil {
		return nil
	}
	h.Reset()
	_, err := packetHeader.Clone().WriteTo(h)
	if err != nil {
		return nil
	}
	_, err = payload.WriteTo(h)
	if err != nil {
		return nil
	}
	return h.Sum(nil)
}

func BinaryMarshalHash(bMarshal encoding.BinaryMarshaler, h hash.Hash) []byte {
	if bMarshal == nil || h == nil {
		return nil
	}
	h.Reset()
	bts, err := bMarshal.MarshalBinary()
	if err != nil {
		return nil
	}
	h.Write(bts)
	return h.Sum(nil)
}
