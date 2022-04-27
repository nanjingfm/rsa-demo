package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func main() {
	keyData, err := ioutil.ReadFile("./private.key")
	keyPair, err := NewRsaKeyPairFromBytes(keyData)

	fmt.Println(string(keyPair.PublicKey()))
	fmt.Println(string(keyPair.PrivateKey()))

	testData := []byte("[12345]")
	encrypt, err := keyPair.Encrypt(testData)
	if err != nil {
		panic(err)
	}
	fmt.Println("密文：")
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))

	var data []int
	err = keyPair.Decrypt(encrypt, &data)
	if err != nil {
		panic(err)
	}
	fmt.Println("明文:")
	fmt.Println(data)
}

func NewRsaKeyPair(privateKey *rsa.PrivateKey) *rsaKeyPair {
	return &rsaKeyPair{privateKey: privateKey}
}

func NewRsaKeyPairFromBytes(data []byte) (*rsaKeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &rsaKeyPair{privateKey: privateKey}, nil
}

type rsaKeyPair struct {
	privateKey *rsa.PrivateKey
	label      []byte
}

func (t *rsaKeyPair) SetLabel(label string) *rsaKeyPair {
	t.label = []byte(label)
	return t
}

func (t *rsaKeyPair) PublicKey() []byte {
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&t.privateKey.PublicKey)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	return pem.EncodeToMemory(publicKeyBlock)
}

func (t *rsaKeyPair) PrivateKey() []byte {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(t.privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	return pem.EncodeToMemory(privateKeyBlock)
}

func (t *rsaKeyPair) Encrypt(data []byte) (encryptedBytes []byte, err error) {
	publicKey := t.privateKey.PublicKey
	encryptedBytes, err = rsa.EncryptPKCS1v15(rand.Reader, &publicKey, data)
	return
}

func (t *rsaKeyPair) Decrypt(encryptBytes []byte, obj interface{}) error {
	decryptData, err := rsa.DecryptPKCS1v15(rand.Reader, t.privateKey, encryptBytes)
	if err != nil {
		return err
	}
	if unmarshalErr := json.Unmarshal(decryptData, obj); unmarshalErr != nil {
		return unmarshalErr
	}

	return nil
}
