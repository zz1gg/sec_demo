package utils

import (
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"log"
)

func GetMD5Hash(target string) string {
	data, err := ioutil.ReadFile(target)
	if err != nil {
		log.Fatalf("Open %s Failed with error: ", target, err)
	}
	//fmt.Printf("Md5: %x\n\n", md5.Sum(data))
	//fmt.Printf("Sha1: %x\n\n", sha1.Sum(data))
	//fmt.Printf("Sha256: %x\n\n", sha256.Sum256(data))
	//fmt.Printf("Sha512: %x\n\n", sha512.Sum512(data))

	hasher := md5.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
