package crypto

import (
	"crypto/rsa"
	"errors"
	"hash"
	"math/big"
)

const RSA_E = 65537
const RSA_MIN_KEY_SIZE = 128

var ErrIncompatibleKey = errors.New("incompatible key")
var ErrKeySizeWrong = errors.New("key size wrong")
var Err2PrimesRequired = errors.New("2 primes required")

func RSAPrivateKeyMarshalBinary(k *rsa.PrivateKey, keyByteSize int) ([]byte, error) {
	if k == nil {
		return nil, ErrKeyNil
	}
	if len(k.Primes) != 2 {
		return nil, Err2PrimesRequired
	}
	toRet := k.N.FillBytes(make([]byte, keyByteSize))
	toRet = append(toRet, k.D.FillBytes(make([]byte, keyByteSize))...)
	toRet = append(toRet, k.Primes[0].FillBytes(make([]byte, keyByteSize/2))...)
	toRet = append(toRet, k.Primes[1].FillBytes(make([]byte, keyByteSize/2))...)
	return toRet, nil
}
func RSAPrivateKeyUnmarshalBinary(k []byte) (*rsa.PrivateKey, error) {
	if k == nil {
		return nil, ErrKeyNil
	}
	if len(k) < RSA_MIN_KEY_SIZE*3 || len(k)%6 != 0 {
		return nil, ErrKeySizeWrong
	}
	toRet := new(rsa.PrivateKey)
	toRet.E = RSA_E
	toRet.N = new(big.Int)
	toRet.D = new(big.Int)
	toRet.N.SetBytes(k[:len(k)/3])
	toRet.D.SetBytes(k[len(k)/3 : 2*(len(k)/3)])
	toRet.Primes = make([]*big.Int, 2)
	toRet.Primes[0] = new(big.Int)
	toRet.Primes[0].SetBytes(k[2*(len(k)/3) : 5*(len(k)/6)])
	toRet.Primes[1] = new(big.Int)
	toRet.Primes[1].SetBytes(k[5*(len(k)/6):])
	return toRet, toRet.Validate()
}

func RSAPublicKeyMarshalBinary(k *rsa.PublicKey, keyByteSize int) ([]byte, error) {
	if k == nil {
		return nil, ErrKeyNil
	}
	return k.N.FillBytes(make([]byte, keyByteSize)), nil
}

func RSAPublicKeyUnmarshalBinary(k []byte) (*rsa.PublicKey, error) {
	if k == nil {
		return nil, ErrKeyNil
	}
	if len(k) < RSA_MIN_KEY_SIZE || len(k)%2 != 0 {
		return nil, ErrKeySizeWrong
	}
	toRet := new(rsa.PublicKey)
	toRet.E = RSA_E
	toRet.N = new(big.Int)
	toRet.N.SetBytes(k)
	return toRet, nil
}

func HashBytes(b []byte, h hash.Hash) []byte {
	if h == nil || b == nil {
		return nil
	}
	h.Reset()
	h.Write(b)
	defer h.Reset()
	return h.Sum(nil)
}
