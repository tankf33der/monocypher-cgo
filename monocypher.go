package main

// #cgo pkg-config: monocypher
// #include <monocypher.h>
// #include <monocypher-ed25519.h>
import "C"
import "unsafe"
import "fmt"

func sha512(in []byte) []byte {
	var ptr unsafe.Pointer
	out := make([]byte, 64)

	if in == nil {
		ptr = unsafe.Pointer(&in)
	} else {
		ptr = unsafe.Pointer(&in[0])
	}

	C.crypto_sha512(
		(*C.uchar)(&out[0]),
		// (*C.uchar)(unsafe.Pointer(&in[0])),
		(*C.uchar)(ptr),
		(C.ulong)(len(in)))
	return out
}

func main() {
	r := []byte{1,1,1,1}
	o := sha512(r)
	fmt.Println("start")
	fmt.Println(o)
}



