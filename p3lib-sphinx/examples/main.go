package main

import (
	sc "github.com/gpestana/p3lib/p3lib-sphinx/crypto"
	"log"
)

func main() {
	h, err := sc.GenerateECDHSharedKey()
	log.Println(err)
	log.Println(h)
}
