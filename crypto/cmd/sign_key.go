// (C) 1f349 2025 - BSD-3-Clause License

package cmd

import (
	"fmt"
	"github.com/1f349/handshake/crypto"
	"hash"
	"io"
	"log"
	"os"
	"strconv"
	"testing"
	"time"
)

const RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

// MainSignKey provides a command for use in main for signing public kem keys using the specified crypto.SigScheme and hash.Hash
func MainSignKey(scheme crypto.SigScheme, dataHash hash.Hash, buildName, buildDate, buildVersion, buildAuthor, buildLicense string) {
	mainSignKey(scheme, dataHash, buildName, buildDate, buildVersion, buildAuthor, buildLicense, os.Exit, os.Stdout, os.Stdin)
}

// TestingMainSignKey provides a way of executing MainSignKey in a test environment
func TestingMainSignKey(scheme crypto.SigScheme, dataHash hash.Hash, buildName, buildDate, buildVersion, buildAuthor, buildLicense string, exit func(code int), stdout *os.File, stdin *os.File) {
	if !testing.Testing() {
		exit(-1)
		return
	}
	mainSignKey(scheme, dataHash, buildName, buildDate, buildVersion, buildAuthor, buildLicense, exit, stdout, stdin)
}

func mainSignKey(scheme crypto.SigScheme, dataHash hash.Hash, buildName, buildDate, buildVersion, buildAuthor, buildLicense string, exit func(code int), stdout *os.File, stdin *os.File) {
	if len(os.Args) < 4 {
		usageSK(buildName, buildDate, buildVersion, buildAuthor, buildLicense, exit)
	} else {
		if os.Args[1] == os.Args[2] && os.Args[1] == "-" {
			usageSK(buildName, buildDate, buildVersion, buildAuthor, buildLicense, exit)
			return
		}
		sigData := &crypto.SigData{}
		if len(os.Args) > 5 {
			sigData.IssueTime = getDateTimeFromString(os.Args[5])
			if sigData.IssueTime.IsZero() {
				log.Println("Issue time is invalid")
				exit(3)
				return
			}
		} else {
			sigData.IssueTime = time.Now()
		}
		if len(os.Args) > 4 {
			sigData.ExpiryTime = getDateTimeWithDurationFromString(os.Args[4], sigData.IssueTime)
			if sigData.ExpiryTime.IsZero() {
				log.Println("Expiry time is invalid")
				exit(2)
				return
			}
		} else {
			sigData.ExpiryTime = sigData.IssueTime.Add(168 * time.Hour)
		}
		var f *os.File
		if os.Args[1] == "-" {
			f = stdin
		} else {
			var err error
			f, err = os.Open(os.Args[1])
			if err != nil {
				log.Println(err)
				exit(4)
				return
			}
		}
		defer func() { _ = f.Close() }()
		var fe *os.File
		if os.Args[2] == "-" {
			fe = stdin
		} else {
			var err error
			fe, err = os.Open(os.Args[2])
			if err != nil {
				log.Println(err)
				exit(4)
				return
			}
		}
		defer func() { _ = fe.Close() }()
		var fo *os.File
		if os.Args[3] == "-" {
			fo = stdout
		} else {
			var err error
			fo, err = os.OpenFile(os.Args[3], os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Println(err)
				exit(4)
				return
			}
		}
		defer func() { _ = fo.Close() }()
		bts, err := io.ReadAll(f)
		if err != nil {
			log.Println(err)
			exit(5)
			return
		}
		k, err := scheme.UnmarshalBinaryPrivateKey(bts)
		if err != nil {
			log.Println(err)
			exit(6)
			return
		}
		sigData.PublicKey, err = io.ReadAll(fe)
		if err != nil {
			log.Println(err)
			exit(7)
			return
		}
		sigData = crypto.NewSigData(sigData.PublicKey, sigData.IssueTime, sigData.ExpiryTime, dataHash, k)
		if sigData == nil {
			log.Println("Signing failed.")
			exit(8)
			return
		}
		out, err := sigData.MarshalBinary()
		if err != nil {
			log.Println(err)
			exit(9)
			return
		}
		_, err = fo.Write(out)
		if err != nil {
			log.Println(err)
			exit(10)
			return
		}
		_ = fo.Sync()
		exit(0)
		return
	}
}

func getDateTimeFromString(txt string) (t time.Time) {
	i, err := strconv.ParseInt(txt, 10, 64)
	if err != nil {
		t, err = time.Parse(RFC3339Milli, txt)
		if err != nil {
			t, err = time.Parse(time.RFC3339, txt)
			if err != nil {
				return time.Time{}
			}
		}
	} else {
		t = time.UnixMilli(i)
	}
	return t
}

func getDateTimeWithDurationFromString(txt string, base time.Time) (t time.Time) {
	i, err := strconv.ParseInt(txt, 10, 64)
	if err != nil {
		d, err := time.ParseDuration(txt)
		if err != nil {
			t, err = time.Parse(RFC3339Milli, txt)
			if err != nil {
				t, err = time.Parse(time.RFC3339, txt)
				if err != nil {
					return time.Time{}
				}
			}
		} else {
			t = base.Add(d)
		}
	} else {
		t = time.UnixMilli(i)
	}
	return t
}

func usageSK(buildName, buildDate, buildVersion, buildAuthor, buildLicense string, exit func(code int)) {
	log.Printf("%s #%s (%s) : (C) %s : %s License\n", buildName, buildVersion, buildDate, buildAuthor, buildLicense)
	fmt.Println("\nUsage:\n" + buildName + " <private signing key path|-> <public encapsulation key path|-> <signature data path|-> [expiry datetime RFC3339(Milli)|expiry duration from issue|expiry in millisecond unix epoch] [issue datetime RFC3339(Milli)|issue in millisecond unix epoch]")
	fmt.Println("Expiry is a duration of 168h unless specified.")
	fmt.Println("Issue is now unless specified.")
	fmt.Println("If both input paths are \"-\", the command will fail.")
	exit(1)
}
