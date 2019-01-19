package sphinx

import (
	"log"
)

type Packet struct{}

func New() *Packet {
	log.Println("p3lib-sphinx")

	return &Packet{}
}
