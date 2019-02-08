package sphinx

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	scrypto "github.com/hashmatter/p3lib/p3lib-sphinx/crypto"
)

type RelayerCtx struct {
	processedTags [][32]byte
	privKey       *ecdsa.PrivateKey
}

func (r *RelayerCtx) ProcessPacket(packet *Packet) error {
	gElement := packet.Header.GroupElement.(*ecdsa.PublicKey)
	sk := scrypto.GenerateECDHSharedSecret(gElement, r.privKey)

	// checks if packet has been processed based on the derived secret key
	tag := sha256.Sum256([]byte(sk[:]))
	if contains(r.processedTags, tag) {
		return fmt.Errorf("Packet already processed, discarding. (tag: %x)", tag)
	}

	// checks header HMAC
	r.processedTags = append(r.processedTags, tag)

	return nil
}

func contains(s [][32]byte, e [32]byte) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
