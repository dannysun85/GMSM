package pkcs12

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

var (
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 3})
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 6})
)

type pbeCipher interface {
	create(key []byte) (cipher.Block, error)

	deriveKey(salt, password []byte, iterations int) []byte

	deriveIV(salt, password []byte, iterations int) []byte
}

type shaWithTripleDESCBC struct{}

func (shaWithTripleDESCBC) create(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key)
}

func (shaWithTripleDESCBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 1, 24)
}

func (shaWithTripleDESCBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 2, 8)
}

type shaWith40BitRC2CBC struct{}

func (shaWith40BitRC2CBC) create(key []byte) (cipher.Block, error) {
	return New(key, len(key)*8)
}

func (shaWith40BitRC2CBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 1, 5)
}

func (shaWith40BitRC2CBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 2, 8)
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

func pbeCipherFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.Block, []byte, error) {
	var cipherType pbeCipher

	switch {
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		cipherType = shaWithTripleDESCBC{}
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		cipherType = shaWith40BitRC2CBC{}
	default:
		return nil, nil, NotImplementedError("algorithm " + algorithm.Algorithm.String() + " is not supported")
	}

	var params pbeParams
	if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, nil, err
	}

	key := cipherType.deriveKey(params.Salt, password, params.Iterations)
	iv := cipherType.deriveIV(params.Salt, password, params.Iterations)

	block, err := cipherType.create(key)
	if err != nil {
		return nil, nil, err
	}

	return block, iv, nil
}

func pbDecrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.BlockMode, int, error) {
	block, iv, err := pbeCipherFor(algorithm, password)
	if err != nil {
		return nil, 0, err
	}

	return cipher.NewCBCDecrypter(block, iv), block.BlockSize(), nil
}

func pbDecrypt(info decryptable, password []byte) (decrypted []byte, err error) {
	cbc, blockSize, err := pbDecrypterFor(info.Algorithm(), password)
	if err != nil {
		return nil, err
	}

	encrypted := info.Data()
	if len(encrypted) == 0 {
		return nil, errors.New("go-pkcs12: empty encrypted data")
	}
	if len(encrypted)%blockSize != 0 {
		return nil, errors.New("go-pkcs12: input is not a multiple of the block size")
	}
	decrypted = make([]byte, len(encrypted))
	cbc.CryptBlocks(decrypted, encrypted)

	psLen := int(decrypted[len(decrypted)-1])
	if psLen == 0 || psLen > blockSize {
		return nil, ErrDecryption
	}

	if len(decrypted) < psLen {
		return nil, ErrDecryption
	}
	ps := decrypted[len(decrypted)-psLen:]
	decrypted = decrypted[:len(decrypted)-psLen]
	if bytes.Compare(ps, bytes.Repeat([]byte{byte(psLen)}, psLen)) != 0 {
		return nil, ErrDecryption
	}

	return
}

type decryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	Data() []byte
}

func pbEncrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.BlockMode, int, error) {
	block, iv, err := pbeCipherFor(algorithm, password)
	if err != nil {
		return nil, 0, err
	}

	return cipher.NewCBCEncrypter(block, iv), block.BlockSize(), nil
}

func pbEncrypt(info encryptable, decrypted []byte, password []byte) error {
	cbc, blockSize, err := pbEncrypterFor(info.Algorithm(), password)
	if err != nil {
		return err
	}

	psLen := blockSize - len(decrypted)%blockSize
	encrypted := make([]byte, len(decrypted)+psLen)
	copy(encrypted[:len(decrypted)], decrypted)
	copy(encrypted[len(decrypted):], bytes.Repeat([]byte{byte(psLen)}, psLen))
	cbc.CryptBlocks(encrypted, encrypted)

	info.SetData(encrypted)

	return nil
}

type encryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	SetData([]byte)
}
