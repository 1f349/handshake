// (C) 1f349 2025 - BSD-3-Clause License

package cmd

import (
	"github.com/1f349/handshake/crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"slices"
	"testing"
)

func TestMainKegGenKem(t *testing.T) {
	genericTest(t, &keyGenTestKem{})
}

func TestMainKegGenSig(t *testing.T) {
	genericTest(t, &keyGenTestSig{})
}

type keyGenTest interface {
	Main(buildName, buildDate, buildVersion, buildAuthor, buildLicense string, exit func(code int), stdout, stdin *os.File)
}

type keyGenTestKem struct{}

func (k keyGenTestKem) Main(buildName, buildDate, buildVersion, buildAuthor, buildLicense string, exit func(code int), stdout *os.File, stdin *os.File) {
	mainKegGenKem(crypto.RSAKem4096Scheme, buildName, buildDate, buildVersion, buildAuthor, buildLicense, exit, stdout, stdin)
}

type keyGenTestSig struct{}

func (k keyGenTestSig) Main(buildName, buildDate, buildVersion, buildAuthor, buildLicense string, exit func(code int), stdout *os.File, stdin *os.File) {
	mainKegGenSig(crypto.RSASig4096Scheme, buildName, buildDate, buildVersion, buildAuthor, buildLicense, exit, stdout, stdin)
}

func genericTest(t *testing.T, test keyGenTest) {
	dir := t.TempDir()
	var genCmds = []string{"g", "gen", "generate", "G", "gEn", "geNERate"}
	var pubCmds = []string{"p", "pub", "public", "P", "pUb", "puBLIc"}
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
	for idx, genCmd := range genCmds {
		t.Run("command - "+genCmd+" - stdout", func(t *testing.T) {
			os.Args = []string{"testing", genCmd, "-"}
			test.Main("a", "b", "c", "d", "e", tFunc, getStdOut(dir), nil)
		})
		t.Run("command - "+genCmd+" - file", func(t *testing.T) {
			os.Args = []string{"testing", genCmd, dir + "/" + genCmd}
			test.Main("a", "b", "c", "d", "e", tFunc, nil, nil)
		})
		assert.NoError(t, copyStdOutToIn(dir))
		t.Run("command - "+pubCmds[idx]+" - stdin - stdout", func(t *testing.T) {
			os.Args = []string{"testing", pubCmds[idx], "-", "-"}
			test.Main("a", "b", "c", "d", "e", tFunc, getStdOut(dir), getStdIn(dir))
		})
		t.Run("command - "+pubCmds[idx]+" - stdin - file", func(t *testing.T) {
			os.Args = []string{"testing", pubCmds[idx], "-", dir + "/" + pubCmds[idx]}
			test.Main("a", "b", "c", "d", "e", tFunc, nil, getStdIn(dir))
		})
		bts, err := os.ReadFile(dir + "/" + pubCmds[idx])
		assert.NoError(t, err)
		assert.True(t, checkStdOut(dir, bts))
		t.Run("command - "+pubCmds[idx]+" - file - stdout", func(t *testing.T) {
			os.Args = []string{"testing", pubCmds[idx], dir + "/" + genCmd, "-"}
			test.Main("a", "b", "c", "d", "e", tFunc, getStdOut(dir), nil)
		})
		t.Run("command - "+pubCmds[idx]+" - file - file", func(t *testing.T) {
			os.Args = []string{"testing", pubCmds[idx], dir + "/" + genCmd, dir + "/" + pubCmds[idx]}
			test.Main("a", "b", "c", "d", "e", tFunc, nil, nil)
		})
		bts, err = os.ReadFile(dir + "/" + pubCmds[idx])
		assert.NoError(t, err)
		assert.True(t, checkStdOut(dir, bts))
	}
	t.Run("usage", func(t *testing.T) {
		os.Args = []string{"testing"}
		test.Main("a", "b", "c", "d", "e", uFunc, nil, nil)
	})
	t.Run("invalid", func(t *testing.T) {
		os.Args = []string{"testing", "abc"}
		test.Main("a", "b", "c", "d", "e", uFunc, nil, nil)
	})
}

func copyStdOutToIn(dir string) error {
	f, err := os.Open(dir + "/stdout")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	o, err := os.OpenFile(dir+"/stdin", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil
	}
	defer func() { _ = o.Close() }()
	_, err = io.Copy(o, f)
	err = o.Sync()
	return err
}

func getStdOut(dir string) *os.File {
	f, err := os.OpenFile(dir+"/stdout", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil
	}
	return f
}

func checkStdOut(dir string, bts []byte) bool {
	f, err := os.Open(dir + "/stdout")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	chk, err := io.ReadAll(f)
	return slices.Equal(bts, chk)
}

func getStdIn(dir string) *os.File {
	f, err := os.Open(dir + "/stdin")
	if err != nil {
		return nil
	}
	return f
}

func writeStdIn(dir string, bts []byte) error {
	f, err := os.OpenFile(dir+"/stdin", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(bts)
	err = f.Sync()
	return err
}
