package main

// #cgo pkg-config: monocypher
// #include <monocypher.h>
// #include <monocypher-ed25519.h>
import "C"
import "fmt"

func sha512(in []byte) []byte {
	out := make([]byte, 64)
	C.crypto_sha512(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&in[0]),
		(C.ulong)(len(in)))
	return out
}

func main() {
	r := []byte{1,1,1,1}
	o := sha512(r)
	fmt.Println("start")
	fmt.Println(o)
}



