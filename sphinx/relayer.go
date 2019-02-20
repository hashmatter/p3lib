package sphinx

import (
	"crypto/ecdsa"
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

// processes packet in a given relayer context. If the packet is processed
// successfully and not the destination, returns a new packet and routing
// information for the next hop.
func (r *RelayerCtx) ProcessPacket(packet *Packet) (bool, *Packet, []byte, error) {
	var isExit bool
	var next Packet
	var finalPayload []byte

	header := packet.Header
	sessionKey := r.privKey
	sKey := scrypto.GenerateECDHSharedSecret(&header.GroupElement, sessionKey)

	// TODO: first verify if group element is part of the curve. this is very
	// important to avoid twist security attacks

	// checks if packet has been processed based on the derived secret key
	tag := sha256.Sum256([]byte(sKey[:]))
	if contains(r.processedTags, tag) {
		return false, &Packet{}, []byte{},
			fmt.Errorf("Packet already processed, discarding. (tag: %x)", tag)
	}

	r.processedTags = append(r.processedTags, tag)

	// computes HMAC of the header payload with the derived key and checks if it
	// coincides with the header's HMAC
	encodedHeader, err := header.GobEncode()
	if err != nil {
		return false, &Packet{}, []byte{}, fmt.Errorf("Encoding header: %v", err)
	}
	hmac := scrypto.ComputeMAC(sKey, encodedHeader)
	valid := scrypto.CheckMAC(encodedHeader, hmac, sKey)
	if valid == false {
		return false, &Packet{}, []byte{},
			fmt.Errorf("Header MAC not valid for derived shared secret. Aborting packet processing.")
	}

	// adds padding (x000) before decrypting

	// decrypts header payload using the derived shared key
	// note: it is safe to use always the same nonce for encryption side since
	// the shared key is used only once (TODO: is this true? how about re-building
	// circuits?)

	// blinds group element for next hop

	//newElement := scrypto.ComputeBlindingFactor(&header.GroupElement, sKey)

	// finally, put together all necessary bits to forward to next relay, namely
	// the packet itself and the routing information

	//next.Header.GroupElement = newElement

	return isExit, &next, finalPayload, nil
}

func contains(s [][32]byte, e [32]byte) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
