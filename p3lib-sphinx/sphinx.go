package sphinx

import (
	"crypto"
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"errors"
	scrypto "github.com/gpestana/p3lib/p3lib-sphinx/crypto"
	"io"
	"math/big"
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

// generates all shared secrets for a given path.
func generateSharedSecrets(circuitPubKeys []crypto.PublicKey,
	sessionKey ecdsa.PrivateKey) ([]scrypto.Hash256, error) {

	curve := scrypto.GetCurve(sessionKey)
	numHops := len(circuitPubKeys)
	if numHops == 0 {
		return []scrypto.Hash256{}, errors.New("Err: A set of relay pulic keys must be provided")
	}
	sharedSecrets := make([]scrypto.Hash256, numHops)

	// set initial conditions

	// first group element, which is an ephemeral public key of the sender. The
	// group element is blinded at each hop
	groupElement := sessionKey.Public().(*ecdsa.PublicKey)

	// derives shared secret for first hop using ECDH with the local session key
	// and the hop's public key
	firstHopPubKey := circuitPubKeys[0].(*ecdsa.PublicKey)
	sharedSecret := scrypto.GenerateECDHSharedSecret(firstHopPubKey, &sessionKey)
	sharedSecrets[0] = sharedSecret

	// compute blinding factor for first hop, by hashing the ephemeral pubkey of
	// the sender and the derived shared secret with the hop
	var blindingF scrypto.Hash256
	blindingF = scrypto.ComputeBlindingFactor(groupElement, sharedSecret)

	// used to derive next group element
	var privElement big.Int
	privElement.SetBytes(sessionKey.D.Bytes())

	// recursively calculates group element, shared secret and blinding factor for
	// each of the remaining hops
	for i := 1; i < numHops; i++ {
		// derives new group element pair. private part of the element is derived
		// with the scalar_multiplication between the blinding factor and the
		// private scalar of the previous group element
		newGroupElement, privElement := deriveGroupElementPair(privElement, blindingF, curve)

		// computes shared secret
		currentHopPubKey := circuitPubKeys[i].(*ecdsa.PublicKey)
		blindedPrivateKey := ecdsa.PrivateKey{*newGroupElement, privElement} // is this correct??
		sharedSecret = scrypto.GenerateECDHSharedSecret(currentHopPubKey, &blindedPrivateKey)

		sharedSecrets[i] = sharedSecret

		// computes next blinding factor
		blindingF = scrypto.ComputeBlindingFactor(newGroupElement, sharedSecret)
	}

	return sharedSecrets, nil
}

func deriveGroupElementPair(privElement big.Int, blindingF scrypto.Hash256, curve ec.Curve) (*ecdsa.PublicKey, *big.Int) {
	var pointBlindingF big.Int
	pointBlindingF.SetBytes(blindingF[:])
	privElement.Mul(&privElement, &pointBlindingF)
	privElement.Mod(&privElement, curve.Params().N)

	x, y := curve.Params().ScalarBaseMult(privElement.Bytes())
	pubkey := ecdsa.PublicKey{curve, x, y}

	return &pubkey, &privElement
}

func copyPublicKey(pk *ecdsa.PublicKey) *ecdsa.PublicKey {
	newPk := ecdsa.PublicKey{}
	newPk.Curve = pk.Curve
	newPk.X = pk.X
	newPk.Y = pk.Y
	return &newPk
}

// ephemeral key is computed by multiplying the public key with a blinding
// factor.
func computeEphKey(pubkey *ecdsa.PublicKey, blindingFactor scrypto.Hash256) *ecdsa.PublicKey {

	return pubkey
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
