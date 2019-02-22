package sphinx

import (
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"crypto/sha256"
	"fmt"
	scrypto "github.com/hashmatter/p3lib/sphinx/crypto"
	ma "github.com/multiformats/go-multiaddr"
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

// processes packet in a given relayer context
func (r *RelayerCtx) ProcessPacket(packet *Packet) (ma.Multiaddr, *Packet, []byte, error) {
	var next Packet
	var emptyAddr ma.Multiaddr
	var finalPayload []byte

	// TODO: first verify if group element is part of the curve. this is very
	// important to avoid ECC twist security attacks

	// TODO: check payload (i.e.packet) HMAC

	sessionKey := r.privKey
	header := packet.Header
	sKey := scrypto.GenerateECDHSharedSecret(&header.GroupElement, sessionKey)

	// checks if packet has been processed based on the derived secret key
	tag := sha256.Sum256([]byte(sKey[:]))
	if contains(r.processedTags, tag) {
		return emptyAddr, &Packet{}, []byte{},
			fmt.Errorf("Packet already processed, discarding. (tag: %x)", tag)
	}

	r.processedTags = append(r.processedTags, tag)

	nextAddr, nextHmac, nextRoutingInfo, err := processHeader(header, sessionKey, sKey)
	if err != nil {
		return nextAddr, &Packet{}, []byte{}, err
	}

	// blind next group element
	curve := ec.P256()
	var blindingF scrypto.Hash256
	blindingF = scrypto.ComputeBlindingFactor(&header.GroupElement, sKey)
	newGroupElement := blindGroupElement(&header.GroupElement, blindingF[:], curve)

	// prepares next header and packet
	var nextHeader Header
	nextHeader.GroupElement = *newGroupElement
	nextHeader.RoutingInfo = nextRoutingInfo
	nextHeader.RoutingInfoMac = nextHmac

	// TODO: decrypt payload
	decryptPayload := packet.Payload

	next.Version = packet.Version
	next.Header = &nextHeader
	next.Payload = decryptPayload

	// TODO: is packetMAC needed?

	return nextAddr, &next, finalPayload, nil
}

func processHeader(header *Header, sessionKey *ecdsa.PrivateKey, sKey scrypto.Hash256) (ma.Multiaddr, [hmacSize]byte, [routingInfoSize]byte, error) {

	var nextAddr ma.Multiaddr
	var nextHmac [hmacSize]byte
	var nextRoutingInfo [routingInfoSize]byte
	routingInfo := header.RoutingInfo

	// check header HMAC
	var routingInfoMac [hmacSize]byte

	macKey := generateEncryptionKey(sKey[:], hashKey)
	var hKey scrypto.Hash256
	copy(hKey[:], macKey)
	copy(routingInfoMac[:], scrypto.ComputeMAC(hKey, routingInfo[:]))

	if equal(routingInfoMac[:], header.RoutingInfoMac[:]) == false {
		return nextAddr, [hmacSize]byte{}, [routingInfoSize]byte{},
			fmt.Errorf("HeaderMAC is not valid: \n %v\n %v\n",
				header.RoutingInfoMac, routingInfoMac)
	}

	// adds padding (x001) before decrypting
	padding := make([]byte, relayDataSize)
	ri := append(routingInfo[:], padding...)

	// decrypts header payload using the derived shared key
	encKey := generateEncryptionKey(sKey[:], encryptionKey)
	nonce := defaultNonce()
	cipher, err := scrypto.GenerateCipherStream(encKey, nonce, streamSize)
	if err != nil {
		return nextAddr, [hmacSize]byte{}, [routingInfoSize]byte{}, err
	}
	xor(ri, ri, cipher)

	naddr := ri[:addrSize]
	nmac := ri[addrSize : addrSize+hmacSize]
	ninfo := ri[addrSize+hmacSize:]

	nextAddr, err = bytesToAddr(naddr)
	if err != nil {
		return nextAddr, [hmacSize]byte{}, [routingInfoSize]byte{},
			fmt.Errorf("(new address re-building) %v", err)
	}

	copy(nextHmac[:], nmac[:])
	copy(nextRoutingInfo[:], ninfo[:])

	return nextAddr, nextHmac, nextRoutingInfo, nil
}

func bytesToAddr(b []byte) (ma.Multiaddr, error) {
	var addr ma.Multiaddr
	var err error

	switch b[0] {
	// IPv4 address
	case 4:
		addr, err = ma.NewMultiaddrBytes(b[:8])
	// IPv6 address
	case 6:
		addr, err = ma.NewMultiaddrBytes(b[:20])
	default:
		return addr, fmt.Errorf("invalid bytes addr %v", b)
	}

	return addr, err
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
