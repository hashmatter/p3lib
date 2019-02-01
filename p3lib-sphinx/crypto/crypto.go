package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
)

type Hash256 [sha256.Size]byte

// generates shared secret using ECDH protocol in an arbitrary curve. The shared
// secret is the hash of the resulting x coordinate of point after scalar
// multiplication between the a ECDSA key pair.
func GenerateECDHSharedSecret(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) (Hash256, error) {
	curvep := pub.Curve.Params()
	x, _ := curvep.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	sk := sha256.Sum256(x.Bytes())
	return sk, nil
}
