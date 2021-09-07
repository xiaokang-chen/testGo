package main

import (
	"fmt"
	"git.woa.com/testGo/utils"
)

func main() {
	prvKey, pubKey := utils.GenRsaKey()
	//fmt.Println(string(prvKey))
	//fmt.Println(string(pubKey))

	plainText := []byte("wo cao ni ma")
	cipher := utils.SignatureRSA(plainText, prvKey)
	//fmt.Println("cipher", cipher, string(cipher))
	ok := utils.VerifyRSA(plainText, cipher, pubKey)
	fmt.Println(ok)
}