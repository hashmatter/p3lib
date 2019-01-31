package crypto

import (
	c "crypto"
	ec "crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

type Hash256 [sha256.Size]byte
type PrivateKey c.PrivateKey
type PublicKey c.PublicKey

// generates shared secret using ECDH protocol in the NIST P-256 curve. The
// shared secret is the an hash of the x coordinate of the point in the
// curve. TODO: SHA256 output implementation, generalize it in the future
func GenerateECDHSharedKey() ([]byte, error) {
	sk := sha256.New()
	r := rand.Reader //SEC: safe?
	curve := ec.P256()
	_, x, _, err := ec.GenerateKey(curve, r)
	if err != nil {
		return []byte{}, err
	}
	sk.Write(x.Bytes())
	return sk.Sum(nil), nil
}
