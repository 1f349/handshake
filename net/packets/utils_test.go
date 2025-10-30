// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOverwriter(t *testing.T) {
	bts := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	ovwr := &overwriter{buff: bts}
	n, err := ovwr.Write([]byte{0, 0})
	assert.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, byte(0), bts[0])
	assert.Equal(t, byte(0), bts[1])
	assert.Equal(t, byte(3), bts[2])
	ovwr.buff = []byte{0, 0}
	ovwr.index = 0
	n, err = ovwr.Write([]byte{1, 2, 3})
	assert.Error(t, err)
	assert.Equal(t, ErrTooMuchData, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, byte(1), ovwr.buff[0])
	assert.Equal(t, byte(2), ovwr.buff[1])
}

func TestWriteReadBuff(t *testing.T) {
	bts := make([]byte, 0, 255)
	for i := 0; i < 255; i++ {
		bts = append(bts, byte(i))
	}
	buff := bytes.NewBuffer(make([]byte, 0, len(bts)))
	n, err := writeBuff(buff, bts)
	assert.NoError(t, err)
	assert.Equal(t, len(bts)+2, n)
	assert.Equal(t, len(bts)+2, len(buff.Bytes()))
	n, err, bts2 := readBuff(buff)
	assert.NoError(t, err)
	assert.Equal(t, len(bts)+2, n)
	assert.Equal(t, bts, bts2)
}

func TestWriteReadNilBuff(t *testing.T) {
	var bts []byte = nil
	buff := bytes.NewBuffer(make([]byte, 0, 1))
	n, err := writeBuff(buff, bts)
	assert.NoError(t, err)
	assert.Equal(t, len(bts)+1, n)
	assert.Equal(t, len(bts)+1, len(buff.Bytes()))
	n, err, bts2 := readBuff(buff)
	assert.NoError(t, err)
	assert.Equal(t, len(bts)+1, n)
	assert.Equal(t, []byte{}, bts2)
}

func TestGetUUID(t *testing.T) {
	a := GetUUID()
	b := [16]byte{}
	assert.NotEqual(t, b, a)
	t.Log(a)
}
