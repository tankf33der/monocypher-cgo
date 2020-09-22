package main

import (
	// #cgo pkg-config: monocypher
	// #include <monocypher.h>
	// #include <monocypher-ed25519.h>
	"C"
	// "fmt"
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

func crypto_blake2b_general(size int, key []byte, data []byte) []byte {
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
	var out []byte
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

/*
func main() {
	var o [64]byte

	r := []byte{1,1,1,1}
	o = crypto_sha512(r[:0])
	o = crypto_sha512(r[:2])
	fmt.Println(o)
}
*/



