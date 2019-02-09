package sphinx

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	scrypto "github.com/hashmatter/p3lib/sphinx/crypto"
	"math/big"
	"testing"
)

func TestNewPacket(t *testing.T) {
	circuitPubKeys := make([]crypto.PublicKey, 1)
	_, pub := ecdsa.GenerateKey(ec.P256(), rand.Reader)
	circuitPubKeys = append(circuitPubKeys, pub)
	payload := []byte("hello sphinx")

	p, err := NewPacket(pub, circuitPubKeys, payload)
	if err != nil {
		t.Error(err)
	}
	if p == nil {
		t.Error("NewPacket_Test: packet not correctly constructed")
	}
}

func TestGenSharedKeys(t *testing.T) {
	// setup
	curve := ec.P256()
	numHops := 2
	circuitPubKeys := make([]crypto.PublicKey, numHops)
	circuitPrivKeys := make([]crypto.PublicKey, numHops)

	privSender, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)
	pubSender := privSender.PublicKey

	for i := 0; i < numHops; i++ {
		pub, priv := generateHopKeys()
		circuitPrivKeys[i] = priv
		circuitPubKeys[i] = pub
	}

	// generateSharedSecrets
	sharedKeys, err := generateSharedSecrets(circuitPubKeys, *privSender)
	if err != nil {
		t.Error(err)
	}

	// if shared keys were properly generated, the 1st hop must be able to 1)
	// generate shared key and 2) blind group element. The 2rd hop must be able to
	// generate shared key from new blind element

	// 1) first hop derives shared key, which must be the same as sharedKeys[0]
	privKey_1 := circuitPrivKeys[0].(*ecdsa.PrivateKey)
	sk_1 := scrypto.GenerateECDHSharedSecret(&pubSender, privKey_1)
	if sk_1 != sharedKeys[0] {
		t.Error(fmt.Printf("First shared key was not properly computed\n> %x\n> %x\n",
			sk_1, sharedKeys[0]))
	}

	// 2) first hop blinds group element for next hop
	blindingF := scrypto.ComputeBlindingFactor(&pubSender, sk_1)
	var privElement big.Int
	privElement.SetBytes(privKey_1.D.Bytes())
	newGroupElement := blindGroupElement(&pubSender, blindingF[:], curve)

	// 3) second hop derives shared key from blinded group element
	privKey_2 := circuitPrivKeys[1].(*ecdsa.PrivateKey)
	sk_2 := scrypto.GenerateECDHSharedSecret(newGroupElement, privKey_2)
	if sk_2 != sharedKeys[1] {
		t.Error(fmt.Printf("Second shared key was not properly computed\n> %x\n> %x\n",
			sk_2, sharedKeys[1]))
	}
}

// TODO
func TestEncodingDecodingPacket(t *testing.T) {}

func TestEncodingDecodingHeader(t *testing.T) {
	pub, _ := generateHopKeys()
	hp := []byte("header payload")
	header := newHeader(pub, hp)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	err := enc.Encode(header)
	if err != nil {
		t.Error(err)
		return
	}

	var headerAfter Header
	err = dec.Decode(&headerAfter)
	if err != nil {
		t.Error(err)
		return
	}

	if string(header.Payload) != string(headerAfter.Payload) {
		t.Error(fmt.Printf("Original and encoded/decoded header payload mismatch:\n >> %v \n >> %v\n",
			string(header.Payload), string(headerAfter.Payload)))
	}

	hGe := header.GroupElement.(*ecdsa.PublicKey)
	haGe := headerAfter.GroupElement.(ecdsa.PublicKey)

	if hGe.Curve.Params().Name != haGe.Curve.Params().Name {
		t.Error(fmt.Printf("Original and encoded/decoded group elements mismatch:\n >> %v \n >> %v\n",
			hGe.Curve.Params().Name, haGe.Curve.Params().Name))
	}

	var diff big.Int
	diff.Sub(hGe.X, haGe.X)
	if diff.Cmp(big.NewInt(0)) != 0 {
		t.Error(fmt.Printf("Original and encoded/decoded group elements mismatch:\n >> %v \n >> %v\n",
			hGe.X, haGe.X))
	}
}

// helpers
func generateHopKeys() (*ecdsa.PublicKey, *ecdsa.PrivateKey) {
	privHop, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)
	pubHop := privHop.Public().(*ecdsa.PublicKey)
	return pubHop, privHop
}
