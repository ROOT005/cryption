package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

//加密
func RsaEncypt(origData []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

//解密
func RsaDecrypt(ciphertext []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)

	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	result, err1 := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	return result, err1
}

func main() {
	var publickey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwQ3THJn9F7NPLBi6hTI3Fwz55
h47jQUVCOL6iqYYkqyAVglYubc6fimhH5UgFoSS0PtEPKz3ZhCGbPjUKcFmDZiNf
T5ZbMCEtVMkdTCTEd8a82seeMTsXk5vHWh5V0sciTD7FE85+MKroBOesU8aGJrsL
hi88yMwcPNMSlnpdNQIDAQAB
-----END PUBLIC KEY-----`)
	var private = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDwQ3THJn9F7NPLBi6hTI3Fwz55h47jQUVCOL6iqYYkqyAVglYu
bc6fimhH5UgFoSS0PtEPKz3ZhCGbPjUKcFmDZiNfT5ZbMCEtVMkdTCTEd8a82see
MTsXk5vHWh5V0sciTD7FE85+MKroBOesU8aGJrsLhi88yMwcPNMSlnpdNQIDAQAB
AoGBAIVwEXVhriH5zA7f2hn/WGXTb+kzHmqcn4iN12Kj4DqRR/pqLs8OcUkuJ4h2
kK9/tdDdamKQU4Nw3PFJdU/c4fkCzmiZBthdlhWf0/b36Pu4iWkH0UOPuwTr8f+O
t7gLvcO4Du00scYNLCtry2U1IspdZ3XwSTAepc6B8UeFC8spAkEA+Znh1oRu4Q0h
bhYFLwazcczBkcmI6eRp5w5TPCAjdaNgfZ81E/Rz53q7//KmJPI+N9pXhThSAv7Z
nE8PfN7Z0wJBAPZsSrXMxoI1JqgbCqOC182o1XN8aBF8tc/W5jw90KkH6KWEDZ4m
zAUeKZJvL7t0QEeKmv60t1/DLi0AWfzfv9cCQQCmaDaN21tFBYkNKPcpxBDsxPMk
rDVwok0Ms5tAkbiyXEsfVX6AoFCJumUOngqwxSQ//nytH8BlqN0R/g+4U6brAkAQ
dDqo2PuIRjRGlUeok1wFh3h5NZ1dTY52SkslSptcLgMCykZ+gOiujs0H0hTF14VT
QZYH29lCs62po5RepjIRAkB0FG7lqfQj+Y+Aa3zo/ZoX2Y0Ybh6hvna5YvDWWGXJ
RlyIUprHr8fYFDBKdaOO4eBjKoLlL31nn2hh/8Z79hzn
-----END RSA PRIVATE KEY-----
`)
	data, err := RsaEncypt([]byte("testxsaaodaw"), publickey)
	data1 := string(data)
	if err != nil {
		fmt.Println("wrong\n")
	}
	result, err1 := RsaDecrypt([]byte(data1), private)
	if err1 != nil {
		fmt.Println("test \n")
	}
	fmt.Println(string(result))
}
