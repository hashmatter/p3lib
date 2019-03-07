package sphinx

import (
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"crypto/sha256"
	"fmt"
	scrypto "github.com/hashmatter/p3lib/sphinx/crypto"
)

type RelayerCtx struct {
	processedTags [][32]byte
	privKey       *ecdsa.PrivateKey
}

func NewRelayerCtx(privKey *ecdsa.PrivateKey) *RelayerCtx {
	return &RelayerCtx{
		processedTags: [][32]byte{},
		privKey:       privKey,
	}
}

// returns list tags of each of the processed packets by the current relay
// context
func (r *RelayerCtx) ListProcessedPackets() [][32]byte {
	return r.processedTags
}

// processes packet in a given relayer context
func (r *RelayerCtx) ProcessPacket(packet *Packet) ([addrSize]byte, *Packet, error) {
	var next Packet
	var emptyAddr [addrSize]byte

	curve := ec.P256()
	header := packet.Header

	// first verify if group element is part of the expected curve. this is very
	// important to avoid ECC twist security attacks
	gElement := &header.GroupElement
	isOnCurve := curve.Params().IsOnCurve(gElement.X, gElement.Y)
	if isOnCurve == false {
		return emptyAddr, &Packet{},
			fmt.Errorf("Potential ECC attack! Group element is not on the expected curve.")
	}

	sessionKey := r.privKey
	sKey := scrypto.GenerateECDHSharedSecret(gElement, sessionKey)

	// checks if packet has been processed based on the derived secret key
	tag := sha256.Sum256([]byte(sKey[:]))
	if contains(r.processedTags, tag) {
		return emptyAddr, &Packet{},
			fmt.Errorf("Packet already processed, discarding. (tag: %x)", tag)
	}

	r.processedTags = append(r.processedTags, tag)

	// process header
	nextAddr, nextHmac, nextRoutingInfo, err := processHeader(header, sessionKey, sKey)
	if err != nil {
		return emptyAddr, &Packet{}, err
	}

	// decrypts payload
	decryptedPayload, err := decryptPayload(packet.Payload, sKey)
	if err != nil {
		return emptyAddr, &Packet{}, err
	}

	// blind next group element
	var blindingF scrypto.Hash256
	blindingF = scrypto.ComputeBlindingFactor(&header.GroupElement, sKey)
	newGroupElement := blindGroupElement(&header.GroupElement, blindingF[:], curve)

	// prepares next header and packet
	var nextHeader Header
	nextHeader.GroupElement = *newGroupElement
	nextHeader.RoutingInfo = nextRoutingInfo
	nextHeader.RoutingInfoMac = nextHmac

	next.Version = packet.Version
	next.Header = &nextHeader
	next.Payload = decryptedPayload

	return nextAddr, &next, nil
}

func processHeader(header *Header, sessionKey *ecdsa.PrivateKey, sKey scrypto.Hash256) ([addrSize]byte, [hmacSize]byte, [routingInfoSize]byte, error) {

	var nextHmac [hmacSize]byte
	var nextAddr [addrSize]byte
	var nextRoutingInfo [routingInfoSize]byte
	routingInfo := header.RoutingInfo

	// generate keys
	encKey := generateEncryptionKey(sKey[:], encryptionKey)
	macKey := generateEncryptionKey(sKey[:], hashKey)

	// check hmac
	var routingInfoMac [hmacSize]byte
	var hKey scrypto.Hash256
	copy(hKey[:], macKey)
	copy(routingInfoMac[:], scrypto.ComputeMAC(hKey, routingInfo[:]))

	if equal(routingInfoMac[:], header.RoutingInfoMac[:]) == false {
		return [addrSize]byte{}, [hmacSize]byte{}, [routingInfoSize]byte{},
			fmt.Errorf("HeaderMAC is not valid: \n %v\n %v\n",
				header.RoutingInfoMac, routingInfoMac)
	}

	// adds padding (x001) before decrypting
	padding := make([]byte, hmacSize+addrSize)
	paddedRi := append(routingInfo[:], padding...)

	// decrypts header payload using the derived shared key
	cipher, err := scrypto.GenerateCipherStream(encKey, defaultNonce(), streamSize)
	if err != nil {
		return [addrSize]byte{}, [hmacSize]byte{}, [routingInfoSize]byte{}, err
	}

	ri, _ := xor(paddedRi, cipher)

	naddr := ri[:addrSize]
	nmac := ri[addrSize:relayDataSize]
	var ninfo [routingInfoSize]byte
	copy(ninfo[:], ri[relayDataSize:])

	copy(nextAddr[:], naddr[:])
	copy(nextHmac[:], nmac[:])
	copy(nextRoutingInfo[:], ninfo[:])

	return nextAddr, nextHmac, nextRoutingInfo, nil
}

func decryptPayload(p [payloadSize]byte, ss scrypto.Hash256) ([payloadSize]byte, error) {
	var resP [payloadSize]byte
	nonce := defaultNonce()
	cipher, err := scrypto.GenerateCipherStream(ss[:], nonce, payloadSize)
	if err != nil {
		return [payloadSize]byte{}, err
	}

	decrP, _ := xor(p[:], cipher)
	copy(resP[:], decrP[:])
	return resP, nil
}

func contains(s [][32]byte, e [32]byte) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, ai := range a {
		if ai != b[i] {
			return false
		}
	}

	return true
}
