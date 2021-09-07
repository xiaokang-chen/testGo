package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	PrivateKeyType = "PRIVATE KEY"
	PublicKeyType = "PUBLIC KEY"
)

// GenRsaKey RSA公钥私钥产生
func GenRsaKey() (prvkey, pubkey []byte) {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  PrivateKeyType,
		Bytes: derStream,
	}
	prvkey = pem.EncodeToMemory(block)
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  PublicKeyType,
		Bytes: derPkix,
	}
	pubkey = pem.EncodeToMemory(block)
	return
}

//--------------------------------------文件流读写-------------------------------------------------
////------1.获取私匙------
////Step1:打开文件获取私匙
//file,err:=os.Open(fileName)
//if err!=nil{
//	panic(err)
//}
//defer file.Close()
//fileinfo,err:=file.Stat()
//if err!=nil{
//	panic(err)
//}
//buf:=make([]byte,fileinfo.Size())
//file.Read(buf)
////Step2:将私匙反pem化
//block,_:=pem.Decode(buf)
////Step3:将私匙反X509序列化
//privkey, err := x509.ParsePKCS1PrivateKey(privateKey)
//if err!=nil{
//	panic(err)
//}
//--------------------------------------文件流读写 END-------------------------------------------------


//------------数字签名------------
func SignatureRSA(plainText []byte, privateKey []byte) []byte {
	//------1.获取明文的散列值------
	//Step1:创建指定哈希函数的Hash接口
	myHash:=sha256.New()
	//Step2:将明文写入myHash结构体
	myHash.Write(plainText)
	//Step3：获得明文的散列值
	hashText:=myHash.Sum(nil)
	//------2.将明文的散列值采用RSA私匙进行签名------
	key, _ := LoadPrivateKey(string(privateKey))
	cipher,err:=rsa.SignPKCS1v15(rand.Reader,key,crypto.SHA256,hashText)
	if err!=nil{
		panic(err)
	}
	return cipher
}

//------------验证数字签名------------
func VerifyRSA(plainText, sigText []byte, publicKey []byte) bool{
	//------1.获取明文的散列值------
	//Step1:创建hash接口，指定采用的哈希函数
	myHash:=sha256.New()
	//Step2:向myHash中写入内容
	myHash.Write(plainText)
	//Step3:生成明文的散列值
	hashText:=myHash.Sum(nil)
	//------2.对数字签名后的内容进行解密------
	key, _ := LoadPublicKey(string(publicKey))
	err := rsa.VerifyPKCS1v15(key,crypto.SHA256,hashText,sigText)
	if err != nil{
		return false
	}else{
		return true
	}
}

// LoadPrivateKey 通过私钥的文本内容加载私钥
func LoadPrivateKey(privateKeyStr string) (privateKey *rsa.PrivateKey, err error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil {
		return nil, fmt.Errorf("decode private key err")
	}
	if block.Type != PrivateKeyType {
		return nil, fmt.Errorf("the kind of PEM should be PRVATE KEY")
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key err:%s", err.Error())
	}
	return privateKey, nil
}

// LoadPublicKey 通过公钥的文本内容加载公钥
func LoadPublicKey(publicKeyStr string) (publicKey *rsa.PublicKey, err error) {
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil {
		return nil, errors.New("decode public key error")
	}
	if block.Type != PublicKeyType {
		return nil, fmt.Errorf("the kind of PEM should be PUBLIC KEY")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key err:%s", err.Error())
	}
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not rsa public key", publicKeyStr)
	}
	return publicKey, nil
}