Lets try to test [monocypher](https://monocypher.org/) library
via [cgo](https://golang.org/cmd/cgo/) against
golang's [crypto](https://golang.org/pkg/crypto/) standart library.

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
$ git clone https://git.envs.net/mpech/monocypher-cgo.git
$ cd monocypher-cgo
$ go test -v
SOME OUTPUT
$

```

Have fun.
