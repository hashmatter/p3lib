package crypto

import (
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestGenerateECDHSharedSecret(t *testing.T) {
	curve := ec.P256()
	r := rand.Reader

	privBob, _ := ecdsa.GenerateKey(curve, r)
	pubBob := privBob.Public().(*ecdsa.PublicKey)

	privAlice, _ := ecdsa.GenerateKey(curve, r)
	pubAlice := privAlice.Public().(*ecdsa.PublicKey)

	sBob := GenerateECDHSharedSecret(pubAlice, privBob)
	sAlice := GenerateECDHSharedSecret(pubBob, privAlice)

	if sBob != sAlice {
		t.Error(fmt.Printf("symmetric shared keys are not the same %v %v", sBob, sAlice))
	}
}
