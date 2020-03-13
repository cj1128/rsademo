package main

import (
	"fmt"
	"log"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type keyPair struct {
	p    int64
	q    int64
	n    int64
	phiN int64
	e    int64
	d    int64
}

func (k *keyPair) String() string {
	result := &strings.Builder{}
	result.WriteString("Key details:\n")
	fmt.Fprintf(result, "  p: %d\n", k.p)
	fmt.Fprintf(result, "  q: %d\n", k.q)
	fmt.Fprintf(result, "  n: %d\n", k.n)
	fmt.Fprintf(result, "  phi(n): %d\n", k.phiN)
	fmt.Fprintf(result, "  e: %d\n", k.e)
	fmt.Fprintf(result, "  d: %d", k.d)

	return result.String()
}

func extEuclid(a, b int64) (int64, int64, int64) {
	var oldS int64 = 1
	var s int64 = 0
	var oldT int64 = 0
	var t int64 = 1
	oldR := a
	r := b

	var tmp int64
	var q int64

	for r != 0 {
		q = oldR / r

		tmp = r
		r = oldR - q*r
		oldR = tmp

		tmp = s
		s = oldS - q*s
		oldS = tmp

		tmp = t
		t = oldT - q*t
		oldT = tmp
	}

	return oldS, oldT, oldR
}

func genKeyPair(pStr, qStr string) (*keyPair, error) {
	p, err := strconv.ParseInt(pStr, 0, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "could not transform '%s' to integer", pStr)
	}

	if !isPrime(p) {
		return nil, fmt.Errorf("%d is not a prime number", p)
	}

	q, err := strconv.ParseInt(qStr, 0, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "could not transform '%s' to integer", qStr)
	}

	if !isPrime(q) {
		return nil, fmt.Errorf("%d is not a prime number", q)
	}

	n := p * q

	phiN := (p - 1) * (q - 1)

	var e int64
	var i int64

	for i = 2; i <= 65537; i++ {
		if isCoprime(i, phiN) {
			e = i
			break
		}
	}

	if e == 0 {
		return nil, errors.New("couldn't find e, search through 2 ~ 65537")
	}

	d := multiplicativeInverse(e, phiN)

	return &keyPair{
		p:    p,
		q:    q,
		n:    n,
		phiN: phiN,
		e:    e,
		d:    d,
	}, nil
}

func multiplicativeInverse(a, b int64) int64 {
	x, _, _ := extEuclid(a, b)
	if x < 0 {
		return x + b
	}

	return x
}

func isCoprime(a, b int64) bool {
	_, _, gcd := extEuclid(a, b)
	return gcd == 1
}

func isPrime(num int64) bool {
	var i int64
	for i = 2; i <= int64(math.Floor(math.Sqrt(float64(num)))); i++ {
		if num%i == 0 {
			return false
		}
	}

	return num > 1
}

func encrypt(pStr, qStr, message string) {
	key, err := genKeyPair(pStr, qStr)
	if err != nil {
		log.Fatalf("couldn't generate key: %v", err)
	}

	fmt.Println(key)
	messageNum, err := strconv.ParseInt(message, 0, 64)
	if err != nil {
		log.Fatalf("couldn't transform message to integer: %v", err)
	}

	if messageNum >= key.n {
		log.Fatalf("message(%d) is >= n(%d)", messageNum, key.n)
	}

	fmt.Printf("Encrypt message: %d\n", messageNum)

	cipher := rsaEncrypt(
		big.NewInt(0).SetInt64(key.n),
		big.NewInt(0).SetInt64(key.e),
		big.NewInt(0).SetInt64(messageNum),
	)

	fmt.Printf("Encrypt result: %d\n", cipher.Int64())
}

func decrypt(pStr, qStr, cipher string) {
	key, err := genKeyPair(pStr, qStr)
	if err != nil {
		log.Fatalf("couldn't generate key: %v", err)
	}

	fmt.Println(key)

	cipherNum, err := strconv.ParseInt(cipher, 0, 64)
	if err != nil {
		log.Fatalln("couldn't transform cipher to integer")
	}

	fmt.Printf("Decrypt cipher: %d\n", cipherNum)

	message := rsaDecrypt(
		big.NewInt(0).SetInt64(key.n),
		big.NewInt(0).SetInt64(key.d),
		big.NewInt(0).SetInt64(cipherNum),
	)

	fmt.Printf("Decrypt result: %d\n", message.Int64())
}

func rsaEncrypt(n, e, m *big.Int) *big.Int {
	return big.NewInt(0).Exp(m, e, n)
}

func rsaDecrypt(n, d, cipher *big.Int) *big.Int {
	return big.NewInt(0).Exp(cipher, d, n)
}
