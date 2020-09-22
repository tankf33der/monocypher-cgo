package main

import (
	"testing"
	"bytes"
	"crypto/sha512"
	"crypto/hmac"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"math/rand"
	"time"
	//"fmt"
)

func TestSha512(t *testing.T) {
	in := make([]byte, 1024)
	var r1, r2 [64]byte

	for i := 0; i < 1024; i++ {
		r1 = crypto_sha512(in[:i])
		r2 = sha512.Sum512(in[:i])
		if (!bytes.Equal(r1[:], r2[:])) {
			t.Errorf("fail sha512, in:%v, r1:%v, r2:%v", in[:i], r1, r2)
		}
	}
}

func TestHmac(t *testing.T) {
	in := make([]byte, 256)
	var r1 [64]byte
	var r2 []byte

	for d := 0; d < 256; d++ {
		for k := 0; k < 256; k++ {
			r1 = crypto_hmac_sha512(in[:k], in[:d])
			mac := hmac.New(sha512.New, in[:k])
			mac.Write(in[:d])
			r2 = mac.Sum(nil)
			if (!bytes.Equal(r1[:], r2[:])) {
				t.Errorf("fail hmac_sha512, in:%v, r1:%v, r2:%v", in[:k], r1, r2)
			}
		}
	}
}

func TestBlake2b(t *testing.T) {
	in := make([]byte, 128)
	var r1 []byte
	var r2 []byte

	for o := 1; o < 64; o++ {
		for d := 0; d < 128; d++ {
			for k := 0; k < 64; k++ {
				r1 = crypto_blake2b_general(o, in[:k], in[:d])
				b, _ := blake2b.New(o, in[:k])
				b.Write(in[:d])
				r2 = b.Sum(nil)
				if (!bytes.Equal(r1[:o], r2[:o])) {
					t.Errorf("fail blake2b, in:%v, r1:%v, r2:%v", in[:k], r1, r2)
				}
			}
		}
	}
}

func TestHChacha20(t *testing.T) {
	var r1, r2 []byte
	key := make([]byte, 32)
	nonce := make([]byte, 16)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 256; i++ {
		rand.Read(key)
		rand.Read(nonce)
		r1 = crypto_hchacha20(key, nonce)
		r2, _ = chacha20.HChaCha20(key, nonce)
		if (!bytes.Equal(r1, r2)) {
			t.Errorf("fail hchacha20, key:%v, nonce:%v", key, nonce)
		}
	}
}
