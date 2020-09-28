package main

import (
	"testing"
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/hmac"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
	"math/rand"
	"time"
)

func TestSha512(t *testing.T) {
	in := make([]byte, 1024)
	var r1, r2 [64]byte

	rand.Seed(time.Now().UnixNano())
	rand.Read(in)
	for i := 0; i < 1024; i++ {
		r1 = crypto_sha512(in[:i])
		r2 = sha512.Sum512(in[:i])
		if (!bytes.Equal(r1[:], r2[:])) {
			t.Errorf("fail sha512, in:%v", in[:i])
		}
	}
}

func TestHmacSha512(t *testing.T) {
	in := make([]byte, 256)
	var r1 [64]byte
	var r2 []byte

	rand.Seed(time.Now().UnixNano())
	rand.Read(in)
	for d := 0; d < 256; d++ {
		for k := 0; k < 256; k++ {
			r1 = crypto_hmac_sha512(in[:k], in[:d])
			mac := hmac.New(sha512.New, in[:k])
			mac.Write(in[:d])
			r2 = mac.Sum(nil)
			if (!bytes.Equal(r1[:], r2[:])) {
				t.Errorf("fail hmac_sha512, in:%v", in[:k])
			}
		}
	}
}

func TestBlake2b(t *testing.T) {
	in := make([]byte, 256)
	var r1 []byte
	var r2 []byte

	rand.Seed(time.Now().UnixNano())
	rand.Read(in)
	for o := 1; o < 64; o++ {
		for d := 0; d < 256; d++ {
			for k := 0; k < 64; k++ {
				r1 = crypto_blake2b_general(uint64(o), in[:k], in[:d])
				b, _ := blake2b.New(o, in[:k])
				b.Write(in[:d])
				r2 = b.Sum(nil)
				if (!bytes.Equal(r1[:o], r2[:o])) {
					t.Errorf("fail blake2b, hash_size: %d, in:%v, data:%v", o, in[:k], in[:d])
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
	for i := 0; i < 1024; i++ {
		rand.Read(key)
		rand.Read(nonce)
		r1 = crypto_hchacha20(key, nonce)
		r2, _ = chacha20.HChaCha20(key, nonce)
		if (!bytes.Equal(r1, r2)) {
			t.Errorf("fail hchacha20, key:%v, nonce:%v", key, nonce)
		}
	}
}

func TestXChacha20_ctr(t *testing.T) {
	var r1, r2 [128]byte
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	text := make([]byte, 128)


	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 1024; i++ {
		rand.Read(key)
		rand.Read(nonce)
		rand.Read(text)
		ctr := rand.Uint32()

		crypto_xchacha20_ctr(r1[:], text, 128, key, nonce, uint64(ctr))
		ch, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
		ch.SetCounter(ctr)
		ch.XORKeyStream(r2[:], text[:])
		if (!bytes.Equal(r1[:], r2[:])) {
			t.Errorf("fail xchacha20_ctr key:%v, nonce:%v", key, nonce)
		}
	}
}

func TestLock(t *testing. T) {
	var r1 [128]byte
	var r2 []byte
	var mac1 [16]byte

	key := make([]byte, 32)
	nonce := make([]byte, 24)
	text := make([]byte, 128)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 1024; i++ {
		rand.Read(key)
		rand.Read(nonce)
		rand.Read(text)

		crypto_lock(mac1[:], r1[:], key, nonce, text, 128)

		aead, _ := chacha20poly1305.NewX(key)
		r2 = aead.Seal(nil, nonce, text, nil)

		if (!bytes.Equal(mac1[:], r2[len(r2)-16:])) {
			t.Errorf("fail mac crypto_lock key:%v, nonce:%v, text:%v", key, nonce, text)
		}
		if (!bytes.Equal(r1[:], r2[:128])) {
			t.Errorf("fail crypto crypto_lock key:%v, nonce:%v, text:%v", key, nonce, text)
		}
	}
}

func TestX25519(t *testing.T) {
	var prv1, pub1 [32]byte
	var prv2, pub2 [32]byte
	var sh1 [32]byte

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 4096; i++ {
		rand.Read(prv1[:])
		rand.Read(prv2[:])

		crypto_x25519_public_key(pub1[:], prv1[:])
		curve25519.ScalarBaseMult(&pub2, &prv2)

		crypto_x25519(sh1[:], prv1[:], pub2[:])
		sh2, _ := curve25519.X25519(prv2[:], pub1[:])
		if (!bytes.Equal(sh1[:], sh2[:])) {
			t.Errorf("fail x25519: pub1:%v, prv1:%v, pub2:%v, prv2:%v", pub1, prv1, pub2, prv2)
		}
	}
}

func TestEd25519All(t *testing.T) {
	var prv, pub []byte
	var text [1024]byte

	rand.Seed(time.Now().UnixNano())
	rand.Read(text[:])
	for i := 0; i < 1024; i++ {
		// public_key
		_, prv, _ = ed25519.GenerateKey(nil)
		pub = crypto_ed25519_public_key(prv[:32])
		if (!bytes.Equal(pub[:], prv[32:])) {
			t.Errorf("fail ed25519 public key: prv:%v", prv)
		}

		// sign
		sg1 := crypto_ed25519_sign(prv[:32], pub, text[:i], uint64(i))
		sg2 := ed25519.Sign(prv, text[:i])
		if (!bytes.Equal(sg1, sg2)) {
			t.Errorf("fail ed25519 sign: prv:%v, text:%v", prv, text[:i])
		}

		// XXX, sg1 and sg2 crossed
		// verify
		r1 := crypto_ed25519_check(sg2, pub, text[:i], uint64(i))
		r2 := ed25519.Verify(prv[32:], text[:i], sg1)

		if (!r2 && r1 != 0) {
			t.Errorf("fail ed25519 verify: prv:%v, text:%v, sg1:%v, sg2:%v", prv, text[:i], sg1, sg2)
		}
	}
}

func TestPoly1305(t *testing.T) {
	var text [1024]byte
	var key [32]byte
	var r2 [16]byte

	rand.Seed(time.Now().UnixNano())
	rand.Read(text[:])

	for i := 0; i < 1024; i++ {
		rand.Read(key[:])

		r1 := crypto_poly1305(text[:i], uint64(i), key[:])
		poly1305.Sum(&r2, text[:i], &key)
		if (!bytes.Equal(r1[:], r2[:])) {
			t.Errorf("fail poly1305: key:%v, text:%v", key, text[:i])
		}
	}
}
