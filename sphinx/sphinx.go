package sphinx

import (
	"bytes"
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"encoding/gob"
	"errors"
	"fmt"
	scrypto "github.com/hashmatter/p3lib/sphinx/crypto"
	"math/big"
)

const (
	// size in bytes of MAC used to verify integrity of header and packet payload
	hmacSize = 32

	// size in bytes for the address of relays and final destination.
	addrSize = 46

	// max number of hops per circuit
	numMaxRelays = 5

	// size in bytes of the next address (n) and size of the hash of the packet (y)
	relayDataSize = addrSize + hmacSize

	// size in bytes for each routing info segment. each segment must be invariant
	// regardless the relay position in the circuit
	routingInfoSize = numMaxRelays * relayDataSize

	// size in bytes of the output of the stream cipher. the output is used to
	// encrypt the header, as well as create the header padding
	streamSize = routingInfoSize + relayDataSize

	// size in bytes of shared secret
	sharedSecretSize = 32

	// packet payload size. this size must be fixed so that all packets keep an
	// invariant size
	payloadSize = 256

	// size in bytes of the realm identifier. a real identifier can be any metadata
	// associeated with the version of the protocol used and us application
	// specific (ie. any developer can define the real version). The realm byte
	// mnust be padded with x0 up to REAL_SIZE
	realmSize = 1
	defRealm  = byte(1)

	// key used to generate cipher stream used to obfuscate the header and
	// payload
	encryptionKey = "encryption"

	// key used to generate cipher stream to calculate hash signature of header
	// and payload
	hashKey = "hash"
)

type Packet struct {
	Version byte
	*Header

	// packet payload has a fixed size and is obfuscated at each hop
	Payload [payloadSize]byte
}

// NewPacket creates a new packet to be forwarded to the first relay in the
// secure circuit. It takes an ephemeral session key, the destination
// information (address and payload) and relay information (public keys and
// addresses) and constructs a cryptographically secure onion packet. The packet
// is then encoded and sent over the wire to the first relay. This is the entry
// point function for an initiator to construct a onion circuit.
func NewPacket(sessionKey *ecdsa.PrivateKey, circuitPubKeys []ecdsa.PublicKey,
	finalAddr []byte, relayAddrs [][]byte, payload [payloadSize]byte) (*Packet, error) {

	if len(circuitPubKeys) == 0 {
		return &Packet{}, errors.New("Err: A set of relay pulic keys must be provided")
	}

	// first, verify if ALL relay group elements are part of the expected curve.
	// this is very important tp avoid ECC twist security attacks
	curve := ec.P256()
	for i, ge := range circuitPubKeys {
		isOnCurve := curve.Params().IsOnCurve(ge.X, ge.Y)
		if isOnCurve == false {
			return &Packet{},
				fmt.Errorf("Potential ECC attack! Group element of relay [%v] is not on the expected curve:", i)
		}
	}

	sharedSecrets, err := generateSharedSecrets(circuitPubKeys, *sessionKey)
	if err != nil {
		return &Packet{}, fmt.Errorf("Shared secrets generation: %v", err)
	}

	header, err := constructHeader(sessionKey, finalAddr, relayAddrs, sharedSecrets)
	if err != nil {
		return &Packet{}, err
	}

	encPayload, err := encryptPayload(payload, sharedSecrets)
	if err != nil {
		return &Packet{}, fmt.Errorf("Encrypting payload: %v", err)
	}

	return &Packet{
		Version: defRealm,
		Header:  header,
		Payload: encPayload,
	}, nil
}

// checks if packet is last in the path. this is verified by inspecting the
// hash of the routing information of the packet's header. if the hash is all
// zeroes, then the current relayer is an exit relay.
func (p *Packet) IsLast() bool {
	hmac := p.Header.RoutingInfoMac
	for _, b := range hmac {
		if b != 0 {
			return false
		}
	}
	return true
}

// Packet encoding auxiliar data structure and logic
type P struct {
	V  byte
	H  []byte
	P  [payloadSize]byte
	Pm [hmacSize]byte
}

func (p *Packet) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)

	he, err := p.Header.GobEncode()
	if err != nil {
		return []byte{}, err
	}

	err = enc.Encode(P{H: he, P: p.Payload})
	if err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

func (p *Packet) GobDecode(raw []byte) error {
	r := bytes.NewReader(raw)
	dec := gob.NewDecoder(r)
	var pbuf P
	err := dec.Decode(&pbuf)
	if err != nil {
		return err
	}

	var header Header
	header.GobDecode(pbuf.H)

	var payload [payloadSize]byte
	copy(payload[:], pbuf.P[:])

	p.Payload = payload
	p.Header = &header
	p.Version = pbuf.V
	return nil
}

// encrypts packet payload in multiple layers using the shared secrets derived
//from the relayers' public keys. the payload will be "peeled" as the packet
// traversed the circuit
func encryptPayload(payload [payloadSize]byte,
	sharedKeys []scrypto.Hash256) ([payloadSize]byte, error) {

	numRelayers := len(sharedKeys)
	nonce := defaultNonce()

	for i := numRelayers - 1; i >= 0; i-- {
		cipher, err := scrypto.GenerateCipherStream(sharedKeys[i][:], nonce, payloadSize)
		if err != nil {
			return [payloadSize]byte{}, err
		}
		p, _ := xor(payload[:], cipher[:])
		copy(payload[:], p[:])
	}
	return payload, nil
}

type Header struct {
	GroupElement   ecdsa.PublicKey
	RoutingInfo    [routingInfoSize]byte
	RoutingInfoMac [hmacSize]byte
}

func constructHeader(sessionKey *ecdsa.PrivateKey, ad []byte,
	circuitAddrs [][]byte, sharedSecrets []scrypto.Hash256) (*Header, error) {

	numRelays := len(circuitAddrs)
	defNonce := defaultNonce()

	validationErrs := validateHeaderInput(numRelays, ad[:])
	if len(validationErrs) != 0 {
		return &Header{}, fmt.Errorf("Header validation errors %v", validationErrs)
	}

	padding, err := generatePadding(sharedSecrets, defNonce)
	if err != nil {
		return &Header{}, fmt.Errorf("Header construction: %v", err)
	}

	var addr [addrSize]byte
	var routingInfo [routingInfoSize]byte
	var hmac [hmacSize]byte

	// adds padding to end of routing info
	copy(routingInfo[routingInfoSize-len(padding):], padding)

	// sets destination address
	copy(addr[:], ad[:])

	for i := numRelays - 1; i >= 0; i-- {
		// generate keys for obfuscate routing info and for generate header HMAC
		encKey := generateEncryptionKey(sharedSecrets[i][:], encryptionKey)
		macKey := generateEncryptionKey(sharedSecrets[i][:], hashKey)

		// first iteration does not need shift right
		if i != numRelays-1 {
			// beta shift right * len(addrHmac) [truncate]
			copy(routingInfo[:], shiftRight(routingInfo[:], relayDataSize))
		}

		var addrHmac [relayDataSize]byte
		copy(addrHmac[:], addr[:])
		copy(addrHmac[len(addr):], hmac[:])

		// add addrHmac to beginning of current routingInfo
		copy(routingInfo[:], addrHmac[:])

		cipher, err := scrypto.GenerateCipherStream(encKey, defNonce, streamSize)
		if err != nil {
			return &Header{}, err
		}

		// obfuscates beta by xoring the last bytes of the cipher stream with the
		// current header information
		r, _ := xor(routingInfo[:], cipher[:routingInfoSize])
		copy(routingInfo[:], r[:])

		// #TODO: comment
		if i == numRelays-1 {
			copy(routingInfo[len(routingInfo)-len(padding):], padding)
		}

		// calculate next hmac
		var hKey scrypto.Hash256
		copy(hKey[:], macKey)
		copy(hmac[:], scrypto.ComputeMAC(hKey, routingInfo[:]))

		// set next address
		copy(addr[:], circuitAddrs[i][:])
	}

	return &Header{sessionKey.PublicKey, routingInfo, hmac}, nil
}

func validateHeaderInput(numRelays int, addr []byte) []error {
	var errs []error

	if numRelays > numMaxRelays {
		errs = append(errs, fmt.Errorf("Maximum number of relays is %v, got %v",
			numMaxRelays, numRelays))
	}

	if len(addr) > addrSize {
		errs = append(errs, fmt.Errorf("Max. size final address is 21 bytes, got %v",
			len(addr)))
	}
	return errs
}

type H struct {
	Ge  []byte
	Ri  [routingInfoSize]byte
	Rim [hmacSize]byte
}

func (h *Header) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)

	pk := h.GroupElement
	element := ec.Marshal(pk.Curve, pk.X, pk.Y)
	err := enc.Encode(H{Ge: element, Ri: h.RoutingInfo, Rim: h.RoutingInfoMac})
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

	curve := ec.P256()
	x, y := ec.Unmarshal(curve, hb.Ge)

	if x == big.NewInt(0) {
		return fmt.Errorf("Err decoding header: group element not using %s curve.", curve.Params().Name)
	}
	pubKey := ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	h.GroupElement = pubKey
	h.RoutingInfo = hb.Ri
	h.RoutingInfoMac = hb.Rim
	return nil
}

func generatePadding(keys []scrypto.Hash256, nonce []byte) ([]byte, error) {
	numRelays := len(keys)
	if numRelays > numMaxRelays {
		return []byte{}, fmt.Errorf("Maximum number of relays is %v, got %v",
			numMaxRelays, len(keys))
	}
	var padding []byte
	for i := 1; i < numRelays; i++ {
		filler := make([]byte, relayDataSize)
		padding = append(padding, filler...)

		key := generateEncryptionKey(keys[i-1][:], encryptionKey)
		cipher, err := scrypto.GenerateCipherStream(key, nonce, streamSize)
		if err != nil {
			return []byte{}, err
		}

		// xor padding with last |padding| bytes of stream data
		padding, _ = xor(padding, cipher[len(cipher)-len(padding):])
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

// generates all shared secrets for a given path.
func generateSharedSecrets(circuitPubKeys []ecdsa.PublicKey,
	sessionKey ecdsa.PrivateKey) ([]scrypto.Hash256, error) {

	curve := scrypto.GetCurve(sessionKey)
	numHops := len(circuitPubKeys)
	if numHops == 0 {
		return []scrypto.Hash256{}, errors.New("Err: A set of relay pulic keys must be provided")
	}
	sharedSecrets := make([]scrypto.Hash256, numHops)

	// first group element, which is an ephemeral public key of the sender. The
	// group element is blinded at each hop
	groupElement := sessionKey.Public().(*ecdsa.PublicKey)

	// derives shared secret for first hop using ECDH with the local session key
	// and the hop's public key
	firstHopPubKey := circuitPubKeys[0]
	sharedSecret := scrypto.GenerateECDHSharedSecret(&firstHopPubKey, &sessionKey)
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
		newGroupElement, nextPrivElement := deriveGroupElementPair(privElement, blindingF, curve)
		// computes shared secret
		currentHopPubKey := circuitPubKeys[i]
		blindedPrivateKey := ecdsa.PrivateKey{
			PublicKey: *newGroupElement,
			D:         &nextPrivElement,
		}
		sharedSecret = scrypto.GenerateECDHSharedSecret(&currentHopPubKey, &blindedPrivateKey)

		sharedSecrets[i] = sharedSecret

		// computes next blinding factor
		blindingF = scrypto.ComputeBlindingFactor(newGroupElement, sharedSecret)

		// sets next private element
		privElement = nextPrivElement
	}
	return sharedSecrets, nil
}

// blinds a group element given a blinding factor and returns both private and
// public keys of the new element
func deriveGroupElementPair(privElement big.Int, blindingF scrypto.Hash256, curve ec.Curve) (*ecdsa.PublicKey, big.Int) {
	var pointBlindingF big.Int
	pointBlindingF.SetBytes(blindingF[:])
	privElement.Mul(&privElement, &pointBlindingF)
	privElement.Mod(&privElement, curve.Params().N)

	x, y := curve.Params().ScalarBaseMult(privElement.Bytes())
	pubkey := ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	return &pubkey, privElement
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

func shiftRight(buf []byte, n int) []byte {
	res := make([]byte, len(buf)+n)
	for i := 0; i < len(buf); i++ {
		res[i+n] = buf[i]
	}
	return res
}

func xor(a, b []byte) ([]byte, int) {
	n := len(a)
	dst := make([]byte, n)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst, n
}

// generates symmetric encryption/decryption keys used to generate the cipher
// stream for xor'ing with plaintext.
func generateEncryptionKey(k []byte, ktype string) []byte {
	var key scrypto.Hash256
	copy(key[:], k[:])
	return scrypto.ComputeMAC(key, []byte(ktype))
}

func defaultNonce() []byte {
	nonce := make([]byte, 24)
	return nonce[:]
}
