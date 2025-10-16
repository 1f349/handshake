// (C) 1f349 2025 - BSD-3-Clause License

package cmd

import (
	"github.com/1f349/handshake/crypto"
	"io"
	"log"
	"os"
	"strings"
	"testing"
)

// MainKegGenKem provides a command for use in main for generating encapsulation keys for the specified crypto.KemScheme
func MainKegGenKem(scheme crypto.KemScheme, buildName, buildDate, buildVersion, buildAuthor, buildLicense string) {
	mainKegGenKem(scheme, buildName, buildDate, buildVersion, buildAuthor, buildLicense, os.Exit, os.Stdout, os.Stdin)
}

// TestingMainKegGenKem provides a way of executing MainKegGenSig in a test environment
func TestingMainKegGenKem(scheme crypto.KemScheme, buildName, buildDate, buildVersion, buildAuthor, buildLicense string, exit func(code int), stdout *os.File, stdin *os.File) {
	if !testing.Testing() {
		exit(-1)
		return
	}
	mainKegGenKem(scheme, buildName, buildDate, buildVersion, buildAuthor, buildLicense, exit, stdout, stdin)
}

func mainKegGenKem(scheme crypto.KemScheme, buildName, buildDate, buildVersion, buildAuthor, buildLicense string, exit func(code int), stdout *os.File, stdin *os.File) {
	if len(os.Args) < 3 {
		usageKG(buildName, buildDate, buildVersion, buildAuthor, buildLicense, exit)
	} else {
		if strings.EqualFold(os.Args[1], "g") || strings.EqualFold(os.Args[1], "gen") || strings.EqualFold(os.Args[1], "generate") {
			var f *os.File
			if os.Args[2] == "-" {
				f = stdout
			} else {
				var err error
				f, err = os.OpenFile(os.Args[2], os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					log.Println(err)
					exit(2)
					return
				}
			}
			defer func() { _ = f.Close() }()
			_, k, err := scheme.GenerateKeyPair()
			if err != nil {
				log.Println(err)
				exit(3)
				return
			}
			var dat []byte
			dat, err = k.MarshalBinary()
			if err != nil {
				log.Println(err)
				exit(3)
				return
			}
			_, err = f.Write(dat)
			if err != nil {
				log.Println(err)
				exit(4)
			}
			_ = f.Sync()
			exit(0)
			return
		} else if len(os.Args) > 3 && (strings.EqualFold(os.Args[1], "p") || strings.EqualFold(os.Args[1], "pub") || strings.EqualFold(os.Args[1], "public")) {
			var f *os.File
			if os.Args[2] == "-" {
				f = stdin
			} else {
				var err error
				f, err = os.Open(os.Args[2])
				if err != nil {
					log.Println(err)
					exit(2)
					return
				}
			}
			defer func() { _ = f.Close() }()
			var fo *os.File
			if os.Args[3] == "-" {
				fo = stdout
			} else {
				var err error
				fo, err = os.OpenFile(os.Args[3], os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Println(err)
					exit(2)
					return
				}
			}
			defer func() { _ = fo.Close() }()
			bts, err := io.ReadAll(f)
			if err != nil {
				log.Println(err)
				exit(3)
				return
			}
			k, err := scheme.UnmarshalBinaryPrivateKey(bts)
			if err != nil {
				log.Println(err)
				exit(4)
				return
			}
			var dat []byte
			dat, err = k.Public().MarshalBinary()
			if err != nil {
				log.Println(err)
				exit(5)
				return
			}
			_, err = fo.Write(dat)
			if err != nil {
				log.Println(err)
				exit(6)
				return
			}
			_ = fo.Sync()
			exit(0)
			return
		} else {
			usageKG(buildName, buildDate, buildVersion, buildAuthor, buildLicense, exit)
		}
	}
}
