package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"net"
)

type P struct {
	M []byte
	K string
}

func handleConnection(conn net.Conn) {
	dec := gob.NewDecoder(conn)
	p := &P{}
	dec.Decode(p)
	fmt.Printf("MSG criptografada : %+v", p.M)
	fmt.Printf("MSG descriptografa : %+v", Decrypter(p.M, p.K))
}

func main() {
	fmt.Println("start")
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		// handle error
	}
	for {
		conn, err := ln.Accept() // this blocks until connection or error
		if err != nil {
			continue
		}
		go handleConnection(conn) // a goroutine handles conn so that the loop can accept other connections
	}
}

func Encrypter(plainText string, key string) []byte {
	keyByte := []byte(key)
	plaintext := []byte(plainText)

	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		panic(err)
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	//Reader is a global, shared instance of a cryptographically strong pseudo-random generator
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	//NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining mode
	mode := cipher.NewCBCEncrypter(block, iv)
	//CryptBlocks encrypts or decrypts a number of blocks.
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	fmt.Printf("%x\n", ciphertext)

	return ciphertext
}

func Decrypter(cipherText []byte, key string) string {
	keyByte := []byte(key)
	ciphertext, _ := hex.DecodeString(cipherText)

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	fmt.Printf("%s\n", ciphertext)
	return cipherText
}
