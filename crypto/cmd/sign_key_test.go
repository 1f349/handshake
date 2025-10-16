// (C) 1f349 2025 - BSD-3-Clause License

package cmd

import (
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"hash"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestMainSignKey(t *testing.T) {
	dir := t.TempDir()
	kemScheme := crypto.RSAKem4096Scheme
	ekp, _, err := kemScheme.GenerateKeyPair()
	assert.NoError(t, err)
	ekpBts, err := ekp.MarshalBinary()
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(dir+"/epubkey", ekpBts, 0644))
	sigScheme := crypto.RSASig4096Scheme
	kp, k, err := sigScheme.GenerateKeyPair()
	assert.NoError(t, err)
	kBts, err := k.MarshalBinary()
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(dir+"/privkey", kBts, 0600))
	tHash := sha256.New()
	var oargs = os.Args
	defer func() {
		os.Args = oargs
	}()
	var tFunc = func(code int) {
		if code != 0 {
			t.Log(code)
			t.FailNow()
		}
	}
	var uFunc = func(code int) {
		if code != 1 {
			t.Log(code)
			t.FailNow()
		}
	}
	t.Run("command privkey epubkey sig", func(t *testing.T) {
		os.Args = []string{"testing", dir + "/privkey", dir + "/epubkey", dir + "/sig"}
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, time.Time{}, tFunc, nil, nil, 0, false)
	})
	t.Run("command privkey epubkey -", func(t *testing.T) {
		os.Args = []string{"testing", dir + "/privkey", dir + "/epubkey", "-"}
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, time.Time{}, tFunc, stdout, nil, 0, false)
	})
	t.Run("command - epubkey sig Now()+1h", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		os.Args = []string{"testing", "-", dir + "/epubkey", dir + "/sig", exp.Format(RFC3339Milli)}
		assert.NoError(t, writeStdIn(dir, kBts))
		stdin := getStdIn(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, exp, tFunc, nil, stdin, 0, false)
	})
	t.Run("command privkey - sig 1h", func(t *testing.T) {
		os.Args = []string{"testing", dir + "/privkey", "-", dir + "/sig", "1h"}
		assert.NoError(t, writeStdIn(dir, ekpBts))
		stdin := getStdIn(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, time.Time{}, tFunc, nil, stdin, 0, false)
	})
	t.Run("command - epubkey - UnixMilli(Now()+1h)", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		os.Args = []string{"testing", "-", dir + "/epubkey", "-", strconv.FormatInt(exp.UnixMilli(), 10)}
		assert.NoError(t, writeStdIn(dir, kBts))
		stdin := getStdIn(dir)
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, exp, tFunc, stdout, stdin, 0, false)
	})
	t.Run("command privkey - - 1h Now()+10ms", func(t *testing.T) {
		iss := time.Now().Add(10 * time.Millisecond)
		exp := iss.Add(time.Hour)
		os.Args = []string{"testing", dir + "/privkey", "-", "-", "1h", iss.Format(RFC3339Milli)}
		assert.NoError(t, writeStdIn(dir, ekpBts))
		stdin := getStdIn(dir)
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, iss, exp, tFunc, stdout, stdin, 50*time.Millisecond, false)
	})
	t.Run("fail-verify privkey - - 1h Now()+1s", func(t *testing.T) {
		iss := time.Now().Add(time.Second)
		exp := iss.Add(time.Hour)
		os.Args = []string{"testing", dir + "/privkey", "-", "-", "1h", iss.Format(RFC3339Milli)}
		assert.NoError(t, writeStdIn(dir, ekpBts))
		stdin := getStdIn(dir)
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, iss, exp, tFunc, stdout, stdin, 0, true)
	})
	t.Run("command privkey - - Now()+1m UnixMilli(Now()+25ms)", func(t *testing.T) {
		iss := time.Now().Add(25 * time.Millisecond)
		exp := iss.Add(time.Minute)
		os.Args = []string{"testing", dir + "/privkey", "-", "-", exp.Format(RFC3339Milli), strconv.FormatInt(iss.UnixMilli(), 10)}
		assert.NoError(t, writeStdIn(dir, ekpBts))
		stdin := getStdIn(dir)
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, iss, exp, tFunc, stdout, stdin, 100*time.Millisecond, false)
	})
	t.Run("Usage", func(t *testing.T) {
		os.Args = []string{"testing"}
		mainSignKey(sigScheme, tHash, "a", "b", "c", "d", "e", uFunc, nil, nil)
	})
	t.Run("Double stdin", func(t *testing.T) {
		os.Args = []string{"testing", "-", "-", "-"}
		mainSignKey(sigScheme, tHash, "a", "b", "c", "d", "e", uFunc, nil, nil)
	})
}

func testMainSignKey(t *testing.T, dir string, sigScheme crypto.SigScheme, hashScheme hash.Hash,
	ekp []byte, kp crypto.SigPublicKey, issue, expiry time.Time, close func(code int), stdout, stdin *os.File, delay time.Duration, failing bool) {
	mainSignKey(sigScheme, hashScheme, "a", "b", "c", "d", "e", close, stdout, stdin)
	if delay > 0 {
		time.Sleep(delay)
	}
	var err error
	var bts []byte
	if stdout == nil {
		bts, err = os.ReadFile(dir + "/sig")
	} else {
		bts, err = os.ReadFile(dir + "/stdout")
	}
	assert.NoError(t, err)
	sd, err := crypto.UnmarshalSigData(bts, ekp)
	assert.NoError(t, err)
	if !issue.IsZero() {
		assert.Equal(t, time.UnixMilli(issue.UnixMilli()), sd.IssueTime)
	}
	if !expiry.IsZero() {
		assert.Equal(t, time.UnixMilli(expiry.UnixMilli()), sd.ExpiryTime)
	}
	v := sd.Verify(hashScheme, kp)
	assert.Equal(t, !failing, v)
}

func TestGetDateTimeFromString(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		dt := getDateTimeFromString("")
		assert.Equal(t, time.Time{}, dt)
	})
	t.Run("Zero", func(t *testing.T) {
		dt := getDateTimeFromString("0")
		assert.Equal(t, time.UnixMilli(0), dt)
	})
	t.Run("One", func(t *testing.T) {
		dt := getDateTimeFromString("1")
		assert.Equal(t, time.UnixMilli(1), dt)
	})
	t.Run("-One", func(t *testing.T) {
		dt := getDateTimeFromString("-1")
		assert.Equal(t, time.UnixMilli(-1), dt)
	})
	t.Run("Invalid", func(t *testing.T) {
		dt := getDateTimeFromString("invalid")
		assert.Equal(t, time.Time{}, dt)
	})
	t.Run("RFC3339", func(t *testing.T) {
		dt := getDateTimeFromString("2006-01-02T15:04:05+07:00")
		et, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")
		assert.NoError(t, err)
		assert.Equal(t, et, dt)
	})
	t.Run("RFC3339Milli", func(t *testing.T) {
		dt := getDateTimeFromString("2006-01-02T15:04:05.989+07:00")
		et, err := time.Parse(RFC3339Milli, "2006-01-02T15:04:05.989+07:00")
		assert.NoError(t, err)
		assert.Equal(t, et, dt)
	})
	t.Run("RFC1123Z-Fail", func(t *testing.T) {
		dt := getDateTimeFromString(time.RFC1123Z)
		et, err := time.Parse(time.RFC1123Z, time.RFC1123Z)
		assert.NoError(t, err)
		assert.NotEqual(t, et, dt)
		assert.True(t, dt.IsZero())
	})
}

func TestGetDateTimeWithDurationFromString(t *testing.T) {
	base := time.Now()
	t.Run("Empty", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("", base)
		assert.Equal(t, time.Time{}, dt)
	})
	t.Run("Zero", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("0", base)
		assert.Equal(t, time.UnixMilli(0), dt)
	})
	t.Run("One", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("1", base)
		assert.Equal(t, time.UnixMilli(1), dt)
	})
	t.Run("-One", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("-1", base)
		assert.Equal(t, time.UnixMilli(-1), dt)
	})
	t.Run("Invalid", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("invalid", base)
		assert.Equal(t, time.Time{}, dt)
	})
	t.Run("RFC3339", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("2006-01-02T15:04:05+07:00", base)
		et, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")
		assert.NoError(t, err)
		assert.Equal(t, et, dt)
	})
	t.Run("RFC3339Milli", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("2006-01-02T15:04:05.989+07:00", base)
		et, err := time.Parse(RFC3339Milli, "2006-01-02T15:04:05.989+07:00")
		assert.NoError(t, err)
		assert.Equal(t, et, dt)
	})
	t.Run("RFC1123Z-Fail", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString(time.RFC1123Z, base)
		et, err := time.Parse(time.RFC1123Z, time.RFC1123Z)
		assert.NoError(t, err)
		assert.NotEqual(t, et, dt)
		assert.True(t, dt.IsZero())
	})
	t.Run("Duration10m", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("10m", base)
		et := base.Add(10 * time.Minute)
		assert.Equal(t, et, dt)
	})
	t.Run("Duration-10m", func(t *testing.T) {
		dt := getDateTimeWithDurationFromString("-10m", base)
		et := base.Add(-10 * time.Minute)
		assert.Equal(t, et, dt)
	})
}
