package main

// This entirety of this file has come from https://github.com/mvdan/bitw/blob/master/crypto.go
// Small changes have been made to satisfy the linter.
// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// Under the BSD 3-Clause license
// https://github.com/mvdan/bitw/blob/d4600876932c7e27feb32b17c83c8f933388c30f/LICENSE

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

type dhGroup struct {
	g, p, pMinus1 *big.Int
}

var bigOne = big.NewInt(1)

func (dg *dhGroup) NewKeypair() (private, public *big.Int, err error) {
	for {
		if private, err = cryptorand.Int(cryptorand.Reader, dg.pMinus1); err != nil {
			return nil, nil, err
		}
		if private.Sign() > 0 {
			break
		}
	}
	public = new(big.Int).Exp(dg.g, private, dg.p)
	return private, public, nil
}

func (dg *dhGroup) diffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	if theirPublic.Cmp(bigOne) <= 0 || theirPublic.Cmp(dg.pMinus1) >= 0 {
		return nil, errors.New("DH parameter out of bounds")
	}
	return new(big.Int).Exp(theirPublic, myPrivate, dg.p), nil
}

func rfc2409SecondOakleyGroup() *dhGroup {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	return &dhGroup{
		g:       new(big.Int).SetInt64(2),
		p:       p,
		pMinus1: new(big.Int).Sub(p, bigOne),
	}
}

func (dg *dhGroup) keygenHKDFSHA256AES128(theirPublic *big.Int, myPrivate *big.Int) ([]byte, error) {
	sharedSecret, err := dg.diffieHellman(theirPublic, myPrivate)
	if err != nil {
		return nil, err
	}

	r := hkdf.New(sha256.New, sharedSecret.Bytes(), nil, nil)
	aesKey := make([]byte, 16)
	if _, err := io.ReadFull(r, aesKey); err != nil {
		return nil, err
	}
	return aesKey, nil
}

func unauthenticatedAESCBCEncrypt(data, key []byte) (iv, ciphertext []byte, _ error) {
	data = padPKCS7(data, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	ivSize := aes.BlockSize
	iv = make([]byte, ivSize)
	ciphertext = make([]byte, len(data))
	if _, err := io.ReadFull(cryptorand.Reader, iv); err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)
	return iv, ciphertext, nil
}

func unauthenticatedAESCBCDecrypt(iv, ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("iv length does not match AES block size")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of AES block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext) // decrypt in-place
	data, err := unpadPKCS7(ciphertext, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func unpadPKCS7(src []byte, size int) ([]byte, error) {
	n := src[len(src)-1]
	if len(src)%size != 0 {
		return nil, fmt.Errorf("expected PKCS7 padding for block size %d, but have %d bytes", size, len(src))
	}
	if len(src) <= int(n) {
		return nil, fmt.Errorf("cannot unpad %d bytes out of a total of %d", n, len(src))
	}
	src = src[:len(src)-int(n)]
	return src, nil
}

func padPKCS7(src []byte, size int) []byte {
	// Note that we always pad, even if rem==0. This is because unpad must
	// always remove at least one byte to be unambiguous.
	rem := len(src) % size
	n := size - rem
	if n > math.MaxUint8 {
		panic(fmt.Sprintf("cannot pad over %d bytes, but got %d", math.MaxUint8, n))
	}
	padded := make([]byte, len(src)+n)
	copy(padded, src)
	for i := len(src); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}
