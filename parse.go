package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"strings"

	"github.com/pkg/errors"
)

type publicKey struct {
	keyType string
	n       *big.Int
	e       *big.Int
}

type privateKey struct {
	keyType string
	n       *big.Int
	e       *big.Int
	d       *big.Int
	p       *big.Int
	q       *big.Int
}

func (k *publicKey) String() string {
	result := &strings.Builder{}
	result.WriteString("OpenSSH Public Key\n")

	result.WriteString(fmt.Sprintf("  keyType: %s\n", k.keyType))
	result.WriteString(fmt.Sprintf("  e: 0x%X\n", k.e.Bytes()))
	result.WriteString(fmt.Sprintf("  n: 0x%X\n", k.n.Bytes()))

	return result.String()
}

func (k *privateKey) String() string {
	result := &strings.Builder{}
	result.WriteString("OpenSSH Private Key\n")

	result.WriteString(fmt.Sprintf("  keyType: %s\n", k.keyType))
	result.WriteString(fmt.Sprintf("  n: 0x%X\n", k.n.Bytes()))
	result.WriteString(fmt.Sprintf("  e: 0x%X\n", k.e.Bytes()))
	result.WriteString(fmt.Sprintf("  d: 0x%X\n", k.d.Bytes()))
	result.WriteString(fmt.Sprintf("  p: 0x%X\n", k.p.Bytes()))
	result.WriteString(fmt.Sprintf("  q: 0x%X\n", k.q.Bytes()))

	return result.String()
}

func read(reader io.Reader, length uint32) []byte {
	result := make([]byte, length)
	n, err := reader.Read(result)
	if err != nil {
		panic(err)
	}
	if uint32(n) != length {
		panic("read error")
	}
	return result
}

// big-endian
func readUint32(reader io.Reader) uint32 {
	var result uint32
	binary.Read(reader, binary.BigEndian, &result)
	return result
}

// return n, e
func parsePublicKey(str string) (*publicKey, error) {
	content := strings.Split(str, " ")[1]
	buf, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode base64")
	}

	reader := bytes.NewReader(buf)
	result := &publicKey{}

	length := readUint32(reader)
	result.keyType = string(read(reader, length))

	length = readUint32(reader)
	result.e = big.NewInt(0).SetBytes(read(reader, length))

	length = readUint32(reader)
	result.n = big.NewInt(0).SetBytes(read(reader, length))

	return result, nil
}

// https://coolaj86.com/articles/the-openssh-private-key-format/
func parsePrivateKey(str string) (*privateKey, error) {
	lines := strings.Split(str, "\n")
	content := strings.Join(lines[1:len(lines)-2], "")
	buf, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, errors.Wrap(err, "couldt not decode base64")
	}

	var length uint32

	result := &privateKey{}
	reader := bytes.NewReader(buf)

	read(reader, 15) // "auth magic"

	// cipher length and string
	length = readUint32(reader)
	read(reader, length)

	// kdfname length and string
	length = readUint32(reader)
	read(reader, length)

	// kdf
	readUint32(reader)

	// number of keys
	readUint32(reader)

	// public key data length
	readUint32(reader)

	// keytype
	length = readUint32(reader)
	result.keyType = string(read(reader, length))

	// e
	length = readUint32(reader)
	result.e = big.NewInt(0).SetBytes(read(reader, length))

	// n
	length = readUint32(reader)
	result.n = big.NewInt(0).SetBytes(read(reader, length))

	// private key data length
	readUint32(reader)

	// dummy
	read(reader, 8)

	// key type
	length = readUint32(reader)
	read(reader, length)

	// n
	length = readUint32(reader)
	read(reader, length)

	// e
	length = readUint32(reader)
	read(reader, length)

	// d
	length = readUint32(reader)
	result.d = big.NewInt(0).SetBytes(read(reader, length))

	// coefficient
	length = readUint32(reader)
	read(reader, length)

	// p
	length = readUint32(reader)
	result.p = big.NewInt(0).SetBytes(read(reader, length))

	// q
	length = readUint32(reader)
	result.q = big.NewInt(0).SetBytes(read(reader, length))

	return result, nil
}

func parse(path string) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	str := string(content)

	if strings.HasPrefix(str, "ssh-rsa") {
		key, err := parsePublicKey(str)
		if err != nil {
			log.Fatalf("couldn't parse openssh public key file: %v", err)
		}
		fmt.Println(key)
	} else if strings.HasPrefix(str, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		key, err := parsePrivateKey(str)
		if err != nil {
			log.Fatalf("couldn't parse openssh private key file: v", err)
		}
		fmt.Println(key)
	} else {
		log.Fatalln(`unknown openssh key format
file should start with 'ssh-rsa' or 
'-----BEGIN OPENSSH PRIVATE KEY-----'`)
	}
}
