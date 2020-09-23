package main

import (
	// #cgo pkg-config: monocypher
	// #include <monocypher.h>
	// #include <monocypher-ed25519.h>
	"C"
	"unsafe"
)

func crypto_sha512(in []byte) [64]byte {
	var out [64]byte
	var in_ptr unsafe.Pointer
	var in_len = len(in)

	if (in_len > 0) {
		in_ptr = unsafe.Pointer(&in[0])
	} else {
		in_ptr = unsafe.Pointer(&in)
	}

	C.crypto_sha512(
		(*C.uchar)(&out[0]),
		(*C.uchar)(in_ptr),
		(C.size_t)(in_len))
	return out
}

func crypto_hmac_sha512(key []byte, data []byte) [64]byte {
	var out [64]byte
	var key_ptr, data_ptr unsafe.Pointer
	var key_len = len(key)
	var data_len = len(data)

	if (key_len > 0) {
		key_ptr = unsafe.Pointer(&key[0])
	} else {
		key_ptr = unsafe.Pointer(&key)
	}

	if (data_len > 0) {
		data_ptr = unsafe.Pointer(&data[0])
	} else {
		data_ptr = unsafe.Pointer(&data)
	}

	C.crypto_hmac_sha512(
		(*C.uchar)(&out[0]),
		(*C.uchar)(key_ptr),
		(C.size_t)(key_len),
		(*C.uchar)(data_ptr),
		(C.size_t)(data_len))
	return out
}

func crypto_blake2b_general(size uint64, key []byte, data []byte) []byte {
	var out [64]byte
	var key_ptr, data_ptr unsafe.Pointer
	var key_len = len(key)
	var data_len = len(data)

	if (key_len > 0) {
		key_ptr = unsafe.Pointer(&key[0])
	} else {
		key_ptr = unsafe.Pointer(&key)
	}

	if (data_len > 0) {
		data_ptr = unsafe.Pointer(&data[0])
	} else {
		data_ptr = unsafe.Pointer(&data)
	}

	C.crypto_blake2b_general(
		(*C.uchar)(&out[0]),
		(C.size_t)(size),
		(*C.uchar)(key_ptr),
		(C.size_t)(key_len),
		(*C.uchar)(data_ptr),
		(C.size_t)(data_len))
	return out[:size]
}

/*
// XXX, deep fatal error of golang and cgo (cannot use _cgo2)
// lets skip for now:
// ./monocypher.go:112:3: cannot use _cgo2 (type *_Ctype_uchar) as type unsafe.Pointer in argument to _Cfunc_crypto_argon2i
// sep.2020, go version go1.15.2 linux/amd64
//
func crypto_argon2(size uint, area []byte, blocks uint, iter uint, pswd []byte, salt []byte) []byte {
	var out [64]byte
	var pswd_ptr, salt_ptr unsafe.Pointer
	var pswd_len = len(pswd)
	var salt_len = len(salt)

	if (pswd_len > 0) {
		pswd_ptr = unsafe.Pointer(&pswd[0])
	} else {
		pswd_ptr = unsafe.Pointer(&pswd)
	}

	if (salt_len > 0) {
		salt_ptr = unsafe.Pointer(&salt[0])
	} else {
		salt_ptr = unsafe.Pointer(&salt)
	}

	C.crypto_argon2i(
		(*C.uchar)(&out[0]),
		(C.uint)(size),
		(*C.uchar)(&area[0]),
		(C.uint)(blocks),
		(C.uint)(iter),
		(*C.uchar)(pswd_ptr),
		(C.uint)(pswd_len),
		(*C.uchar)(salt_ptr),
		(C.uint)(salt_len))
	return out[:size]
}
*/

func crypto_hchacha20(key []byte, nonce []byte) []byte {
	var out [32]byte

	C.crypto_hchacha20(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&key[0]),
		(*C.uchar)(&nonce[0]))
	return out[:]
}

func crypto_xchacha20_ctr(
	c []byte, t []byte, size uint64, key []byte, nonce []byte, ctr uint64) {

	C.crypto_xchacha20_ctr(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&t[0]),
		(C.size_t)(size),
		(*C.uchar)(&key[0]),
		(*C.uchar)(&nonce[0]),
		(C.size_t)(ctr))
}

func crypto_lock(mac []byte, c []byte, key []byte, nonce[]byte, t []byte, size uint64) {
	C.crypto_lock(
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&c[0]),
		(*C.uchar)(&key[0]),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&t[0]),
		(C.size_t)(size))
}

func crypto_x25519(out []byte, prv []byte, pub []byte) {
	C.crypto_x25519(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&prv[0]),
		(*C.uchar)(&pub[0]))
}

func crypto_x25519_public_key(out []byte, prv []byte) {
	C.crypto_x25519_public_key(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&prv[0]))
}

func crypto_ed25519_public_key(prv []byte) []byte{
	var out [32]byte
	C.crypto_ed25519_public_key(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&prv[0]))
	return out[:]
}

func crypto_ed25519_sign(
	prv []byte, pub []byte, data []byte, size uint64) []byte {

	var out [64]byte
	var data_ptr unsafe.Pointer
	var data_len = len(data)

	if (data_len > 0) {
		data_ptr = unsafe.Pointer(&data[0])
	} else {
		data_ptr = unsafe.Pointer(&data)
	}

	C.crypto_ed25519_sign(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&prv[0]),
		(*C.uchar)(&pub[0]),
		(*C.uchar)(data_ptr),
		(C.size_t)(size))
	return out[:]
}

func crypto_ed25519_check(sig []byte, pub []byte, data []byte, size uint64) int {
	var data_ptr unsafe.Pointer
	var data_len = len(data)

	if (data_len > 0) {
		data_ptr = unsafe.Pointer(&data[0])
	} else {
		data_ptr = unsafe.Pointer(&data)
	}
	return int(C.crypto_ed25519_check(
		(*C.uchar)(&sig[0]),
		(*C.uchar)(&pub[0]),
		(*C.uchar)(data_ptr),
		(C.size_t)(size)))
}

func crypto_poly1305(data []byte, size uint64, key []byte) []byte {
	var out [16]byte
	var data_ptr unsafe.Pointer
	var data_len = len(data)

	if (data_len > 0) {
		data_ptr = unsafe.Pointer(&data[0])
	} else {
		data_ptr = unsafe.Pointer(&data)
	}

	C.crypto_poly1305(
		(*C.uchar)(&out[0]),
		(*C.uchar)(data_ptr),
		(C.size_t)(size),
		(*C.uchar)(&key[0]))
	return out[:]
}
