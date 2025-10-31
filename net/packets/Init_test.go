// (C) 1f349 2025 - BSD-3-Clause License

package packets

import "github.com/1f349/handshake/crypto"

type initTestID int

const (
	initTestValid2 initTestID = iota
	initTestValid2B
	initTestValid2A
	initTestValid2AB
	initTestInvalid2
	initTestInvalid2B
)

var validInitKey crypto.KemPrivateKey
var invalidInitKey crypto.KemPrivateKey
var initPacketPayload = [6]*InitPayload{}

func GetValidInitKey(id initTestID) crypto.KemPrivateKey {
	switch id {
	case initTestInvalid2, initTestInvalid2B:
		if invalidInitKey == nil {
			scheme := crypto.RSAKem4096Scheme
			var err error
			_, invalidInitKey, err = scheme.GenerateKeyPair()
			if err != nil {
				panic(err)
			}
		}
		return invalidInitKey
	default:
		if validInitKey == nil {
			scheme := crypto.RSAKem4096Scheme
			var err error
			_, validInitKey, err = scheme.GenerateKeyPair()
			if err != nil {
				panic(err)
			}
		}
		return validInitKey
	}
}

//TODO: Tests
