Lets try to test [monocypher](https://monocypher.org/) library
via [cgo](https://golang.org/cmd/cgo/) against
golang's [crypto](https://golang.org/pkg/crypto/) standart library.

Target host: Linux, x64, go 1.15.2

How to repeat:
```
$ git clone https://github.com/LoupVaillant/Monocypher.git
$ cd Monocypher
$ make test
$ make USE_ED25519=true
$ sudo make install
$ cp src/optional/monocypher-ed25519.h /usr/local/include # XXX
$ cd ~
$ go get "golang.org/x/crypto/blake2b"
$ go get "golang.org/x/crypto/chacha20"
$ go get "golang.org/x/crypto/chacha20poly1305"
$ go get "golang.org/x/crypto/curve25519"
$ go get "golang.org/x/crypto/poly1305"
$ git clone https://git.envs.net/mpech/monocypher-cgo.git
$ cd monocypher-cgo
$ go test -v
=== RUN   TestSha512
--- PASS: TestSha512 (0.00s)
=== RUN   TestHmacSha512
--- PASS: TestHmacSha512 (0.93s)
=== RUN   TestBlake2b
--- PASS: TestBlake2b (2.00s)
=== RUN   TestHChacha20
--- PASS: TestHChacha20 (0.00s)
=== RUN   TestXChacha20_ctr
--- PASS: TestXChacha20_ctr (0.01s)
=== RUN   TestLock
--- PASS: TestLock (0.01s)
=== RUN   TestX25519
--- PASS: TestX25519 (0.51s)
=== RUN   TestEd25519All
--- PASS: TestEd25519All (0.08s)
=== RUN   TestPoly1305
--- PASS: TestPoly1305 (0.00s)
PASS
ok  	_/home/mpech/monocypher-cgo	3.542s
$
```



Have fun.
