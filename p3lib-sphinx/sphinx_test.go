package sphinx

import (
	"crypto"
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"crypto/rand"
	//scrypto "github.com/gpestana/p3lib/p3lib-sphinx/crypto"
	//scrypto "github.com/hashmatter/p3lib/p3lib-sphinx/crypto"
	"testing"
)

func TestNewPacket(t *testing.T) {
	p := New()
	if p == nil {
		t.Error("NewPacket_Test: packet not correctly constructed")
	}
}

func TestGenSharedKeys(t *testing.T) {
	// setup
	circuitPubKeys := make([]crypto.PublicKey, 1)

	privSender, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)
	privHop, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)
	pubHop := privHop.Public().(*ecdsa.PublicKey)
	circuitPubKeys[0] = pubHop

	// generateSharedSecrets
	sk, err := generateSharedSecrets(circuitPubKeys, *privSender)
	if err != nil {
		t.Error(err)
	}

	t.Error(sk)
}
