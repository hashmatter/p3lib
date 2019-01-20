package sphinx

import (
	"crypto/rsa"
	"log"
)

const (
	hmacSize = 32
)

// A sphinx packet wraps the encrypted layers for each of the relays to decrypt and
// retrieve routing data necessary to forward the packet to the next relay. The
// packet does not leak information about the identity of previous and next
// relays and position of the relay in the path. The source node and each of the
// relays perform ECDH to derive a secret key which is used to 1) verify the MAC of
// the header; 2) decrypt the set of routing information needed by the relay and 3)
// shuffle the ephemeral key for the next hop.
type Packet struct {
	Version      byte
	EphemeralKey rsa.PublicKey
	RoutingInfo  routingData
	HeaderMAC    [hmacSize]byte
}

type routingData struct{}

func New() *Packet {
	log.Println("sphinx")
	return &Packet{}
}
