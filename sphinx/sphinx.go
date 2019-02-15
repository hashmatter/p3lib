package sphinx

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"encoding/gob"
	"errors"
	"fmt"
	scrypto "github.com/hashmatter/p3lib/sphinx/crypto"
	"math/big"
	"net"
)

// TODO: in the future, allow for more number of hops. when that is the case,
// migrate these constants into configurations with sensible defaults
const (

	// security parameter in bytes, defines the length of the symmetric key.
	secK = 16

	// size in bytes of MAC used to verify integrity of packet
	hmacSize = 32

	// size in bytes of address of relays and destination
	addrSize = 32

	// size in bytes of the encoded group element (1 + 2*curve_bit_size). this
	// const is for P256
	groupElementSize = 513

	// max number of hops per circuit
	numMaxRelays = 5

	relayDataSize = (addrSize + hmacSize)

	// size in bytes for each routing info segment. each segment must be invariant
	// regardless the relay position in the circuit
	routingInfoSize = numMaxRelays * relayDataSize

	// size in bytes of the output of the stream cipher. the output is used to
	// encrypt the header, as well as create the header padding
	streamSize = routingInfoSize + relayDataSize

	// size in bytes of shared secret
	sharedSecretSize = 32

	// size in bytes of the realm identifier. a real identifier can be any metadata
	// associeated with the version of the protocol used and us application
	// specific (ie. any developer can define the real version). The realm byte
	// mnust be padded with x0 up to REAL_SIZE
	realmSize = 1
	defRealm  = byte(1)
	defNonce  = "0"
)

type Packet struct {
	Version byte
	Header
	Payload []byte
}

func NewPacket(groupElement crypto.PublicKey, circuitPubKeys []crypto.PublicKey, routingInfo [routingInfoSize]byte) (*Packet, error) {
	if len(circuitPubKeys) == 0 {
		return &Packet{}, errors.New("Err: A set of relay pulic keys must be provided")
	}

	header := Header{
		GroupElement: groupElement,
		RoutingInfo:  routingInfo,
	}

	return &Packet{
		Version: defRealm,
		Header:  header,
	}, nil
}

type Header struct {
	GroupElement crypto.PublicKey
	RoutingInfo  [routingInfoSize]byte
	HeaderMac    [hmacSize]byte
}

func newHeader(gElement crypto.PublicKey, addr net.Addr,
	circuitPubKeys []crypto.PublicKey) (*Header, error) {
	var header Header

	sKeys, err := generateSharedSecrets(circuitPubKeys, gElement.(ecdsa.PrivateKey))
	if err != nil {
		return &Header{}, fmt.Errorf("Header construction: %v", err)
	}

	padding, err := generatePadding(sKeys, []byte(defNonce))
	if err != nil {
		return &Header{}, fmt.Errorf("Header construction: %v", err)
	}
	fmt.Println(padding)

	numHops := len(sKeys)
	for i := numHops - 1; i < 0; i-- {

	}

	return &header, nil
}

// generates the padding which is used to keep the header lenght invariant along
// the circuit.
func generatePadding(keys []scrypto.Hash256, nonce []byte) ([]byte, error) {
	paddingSize := (numMaxRelays - 1) * relayDataSize
	padding := make([]byte, paddingSize)

	for i := 1; i < len(keys); i++ {
		key := generateEncryptionKey(keys[i-1][:])
		stream, err := scrypto.GenerateCipherStream(key, nonce, streamSize)
		if err != nil {
			return []byte{}, err
		}

		xor(padding, padding, stream[len(stream)-relayDataSize:])
	}

	return padding, nil
}

// returns HMAC-SHA-256 of the header
func (h *Header) Mac(key scrypto.Hash256) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(h)
	return buf.Bytes()
}

type H struct {
	Ge []byte
	Ri [routingInfoSize]byte
}

func (h *Header) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)

	pk := h.GroupElement.(*ecdsa.PublicKey)
	element := ec.Marshal(pk.Curve, pk.X, pk.Y)
	err := enc.Encode(H{Ge: element, Ri: h.RoutingInfo})
	if err != nil {
		return nil, fmt.Errorf("Err encoding header: %s", err)
	}
	return buf.Bytes(), nil
}

func (h *Header) GobDecode(raw []byte) error {
	r := bytes.NewReader(raw)
	dec := gob.NewDecoder(r)

	var hb H
	err := dec.Decode(&hb)
	if err != nil {
		return fmt.Errorf("Err decoding header: %s", err)
	}

	// TODO: parameterize this to allow for diff curves
	curve := ec.P256()
	x, y := ec.Unmarshal(curve, hb.Ge)
	// if x coordinate is (big.Int) 0, the curves do not match
	if x == big.NewInt(0) {
		return fmt.Errorf("Err decoding header: group element not using %s curve.", curve.Params().Name)
	}
	h.GroupElement = ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	h.RoutingInfo = hb.Ri
	return nil
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
		blindedPrivateKey := ecdsa.PrivateKey{
			PublicKey: *newGroupElement,
			D:         privElement,
		}
		sharedSecret = scrypto.GenerateECDHSharedSecret(currentHopPubKey, &blindedPrivateKey)

		sharedSecrets[i] = sharedSecret

		// computes next blinding factor
		blindingF = scrypto.ComputeBlindingFactor(newGroupElement, sharedSecret)
	}
	return sharedSecrets, nil
}

// blinds a group element given a blinding factor and returns both private and
// public keys of the new element
func deriveGroupElementPair(privElement big.Int, blindingF scrypto.Hash256, curve ec.Curve) (*ecdsa.PublicKey, *big.Int) {
	var pointBlindingF big.Int
	pointBlindingF.SetBytes(blindingF[:])
	privElement.Mul(&privElement, &pointBlindingF)
	privElement.Mod(&privElement, curve.Params().N)

	x, y := curve.Params().ScalarBaseMult(privElement.Bytes())
	pubkey := ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	return &pubkey, &privElement
}

// blinds a group element given a blinding factor but returns only the public
// key. this is a special case of deriveGroupElementPair() which does not
// compute the private key of the blinded element. because of that, this
// function is more efficient and suitable for relays
func blindGroupElement(el *ecdsa.PublicKey, blindingF []byte, curve ec.Curve) *ecdsa.PublicKey {
	newX, newY := curve.Params().ScalarMult(el.X, el.Y, blindingF)
	return &ecdsa.PublicKey{Curve: curve, X: newX, Y: newY}
}

func copyPublicKey(pk *ecdsa.PublicKey) *ecdsa.PublicKey {
	newPk := ecdsa.PublicKey{}
	newPk.Curve = pk.Curve
	newPk.X = pk.X
	newPk.Y = pk.Y
	return &newPk
}

// xor function
func xor(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// generates symmetric encryption/decryption keys used to generate the cipher
// stream for xor'ing with plaintext.
func generateEncryptionKey(k []byte) []byte {
	var key scrypto.Hash256
	copy(key[:], k[:])
	keyPayload := []byte("key")
	return scrypto.ComputeMAC(key, keyPayload)
}
