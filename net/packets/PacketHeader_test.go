// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestPacketHeader(t *testing.T) {
	cTime := time.Now()
	header := PacketHeader{ID: ZeroReservedPacketType, ConnectionUUID: GetUUID(), Time: MilliTime(cTime)}
	var valid, invalid, zero, truncated []byte
	buff := new(bytes.Buffer)
	n, err := header.WriteTo(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(HeaderSize), n)
	valid = make([]byte, buff.Len())
	invalid = make([]byte, HeaderSizeForFragmentation)
	zero = make([]byte, HeaderSize)
	truncated = make([]byte, HeaderSize-2)
	copy(valid, buff.Bytes())
	copy(invalid, buff.Bytes())
	copy(truncated, buff.Bytes())
	invalid[0] = 128
	t.Log(header)
	buff = bytes.NewBuffer(valid)
	rHeader := PacketHeader{}
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.NoError(t, err)
	assert.Equal(t, int64(HeaderSize), n)
	assert.True(t, rHeader.Equals(header))
	assert.True(t, rHeader.IsFragment() == header.IsFragment())
	buff = bytes.NewBuffer(invalid)
	rHeader.Clear()
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.NoError(t, err)
	assert.NotEqual(t, int64(HeaderSize), n)
	assert.True(t, rHeader.Equals(header))
	assert.False(t, rHeader.IsFragment() == header.IsFragment())
	buff = bytes.NewBuffer(zero)
	rHeader.Clear()
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.NoError(t, err)
	assert.Equal(t, int64(HeaderSize), n)
	assert.False(t, rHeader.Equals(header))
	buff = bytes.NewBuffer(truncated)
	rHeader.Clear()
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.Error(t, err)
	assert.Equal(t, int64(HeaderSize-2), n)
	assert.False(t, rHeader.Equals(header))
	assert.True(t, header.Equals(*header.Clone()))
}

func TestPacketHeaderWithFragment(t *testing.T) {
	cTime := time.Now()
	header := PacketHeader{ID: ZeroReservedPacketType, ConnectionUUID: GetUUID(), Time: MilliTime(cTime)}
	header = *header.CloneAsFragment(1, 2, 24)
	var valid, invalid, cloned, zero, truncated []byte
	buff := new(bytes.Buffer)
	n, err := header.WriteTo(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(HeaderSizeForFragmentation), n)
	valid = make([]byte, buff.Len())
	invalid = make([]byte, HeaderSize)
	cloned = make([]byte, HeaderSize)
	zero = make([]byte, HeaderSizeForFragmentation)
	truncated = make([]byte, HeaderSizeForFragmentation-2)
	copy(valid, buff.Bytes())
	copy(invalid, buff.Bytes())
	copy(truncated, buff.Bytes())
	buff = new(bytes.Buffer)
	n, err = header.Clone().WriteTo(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(HeaderSize), n)
	copy(cloned, buff.Bytes())
	invalid[0] = 0
	t.Log(header)
	buff = bytes.NewBuffer(valid)
	rHeader := PacketHeader{}
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.NoError(t, err)
	assert.Equal(t, int64(HeaderSizeForFragmentation), n)
	assert.True(t, headerFragmentedEquals(header, rHeader))
	buff = bytes.NewBuffer(invalid)
	rHeader.Clear()
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.NoError(t, err)
	assert.NotEqual(t, int64(HeaderSizeForFragmentation), n)
	assert.False(t, headerFragmentedEquals(header, rHeader))
	buff = bytes.NewBuffer(cloned)
	rHeader.Clear()
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.NoError(t, err)
	assert.Equal(t, int64(HeaderSize), n)
	assert.True(t, header.Equals(rHeader))
	assert.False(t, headerFragmentedEquals(header, rHeader))
	buff = bytes.NewBuffer(zero)
	rHeader.Clear()
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.NoError(t, err)
	assert.Equal(t, int64(HeaderSize), n)
	assert.False(t, headerFragmentedEquals(header, rHeader))
	buff = bytes.NewBuffer(truncated)
	rHeader.Clear()
	n, err = rHeader.ReadFrom(buff)
	t.Log(rHeader)
	assert.Error(t, err)
	assert.Equal(t, int64(HeaderSizeForFragmentation-2), n)
	assert.True(t, rHeader.Equals(header))
	assert.False(t, headerFragmentedEquals(header, rHeader))
	assert.True(t, header.Equals(*header.Clone()))
	assert.False(t, headerFragmentedEquals(header, *header.Clone()))
}
func headerFragmentedEquals(header PacketHeader, rHeader PacketHeader) bool {
	return rHeader.Equals(header) && rHeader.fragmentIndex == header.fragmentIndex && rHeader.fragmentCount == header.fragmentCount && rHeader.fragmentSize == header.fragmentSize
}
