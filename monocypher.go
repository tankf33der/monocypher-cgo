package main

import (
	// #cgo pkg-config: monocypher
	// #include <monocypher.h>
	"C"
	//"unsafe"
	"fmt"
)

func sha512(in []byte) []byte {
	out := make([]byte, 64)
	C.crypto_sha512(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&in[0]),
		(C.ulonglong)(len(in)))
	return out
}

func main() {
	o := sha512(nil)
	fmt.Println("start")
	fmt.Println(o)
}



