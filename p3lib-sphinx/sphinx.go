package sphinx

import (
	"crypto"
	scrypto "github.com/gpestana/p3lib/p3lib-sphinx/crypto"
	"io"
)

const (
	// security parameter
	sec_k    = 128
	hmacSize = 32

	// NumMaxHops is the maximum circuit length. All packets must have NumMaxHops
	// hop information
	NumMaxHops = 15
)

// A sphinx packet wraps the encrypted layers for each of the relays to decrypt and
// retrieve routing data necessary to forward the packet to the next relay. The
// packet does not leak information about the identity of previous and next
// relays and position of the relay in the path. The source node and each of the
// relays perform ECDH to derive a secret key which is used to 1) verify the MAC of
// the header; 2) decrypt the set of routing information needed by the relay and 3)
// shuffle the ephemeral key for the next hop.
type Packet struct {
	Version byte

	// public key used by each realyer together with its private key to derive the
	// shared secret key used to check the integrity of the packet (with HMAC) and
	// decrypt the routing information
	EphemeralKey crypto.PublicKey

	// arbitrary metadata accessible by any relayer (unencrypted)
	Metadata []byte

	// list of addresses and public keys of relayers that will construct the
	// secure communication channel. The order in the slice maps to the order in
	// the circuit. This data MUST be private and not encoded (TODO: remove from here?)
	routingInfo []peerRoutingInfo
}

func New() *Packet {
	return &Packet{}
}

func generateSharedSecrets(circuitPubKeys []crypto.PublicKey, sessionKey crypto.PrivateKey) ([]scrypto.Hash256, error) {

	numHops := len(circuitPubKeys)
	generatedSecretKeys := make([]scrypto.Hash256, numHops)

	return generatedSecretKeys, nil
}

// HopData contains the routing information for each relayer to forward the
// packet in the circuit. It has with fixed size.
type HopData struct {
	//
}

func (hd *HopData) Encode(w io.Writer) error {
	return nil
}
func (hd *HopData) Decode(r io.Reader) error {
	return nil
}

// ploaceholder for peer routing information, namely its network address and its
// publickey
type peerRoutingInfo struct{}
