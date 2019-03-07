package sphinx

import (
	"bytes"
	"crypto/ecdsa"
	ec "crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	scrypto "github.com/hashmatter/p3lib/sphinx/crypto"
	"math/big"
	"testing"
)

func TestPacketEncoding(t *testing.T) {
	numRelays := 2
	finalAddr := []byte("/ip4/127.0.0.1/udp/1234")
	relayAddrs := [][]byte{
		[]byte("/ip6/2607:f8b0:4003:c01::6a/udp/5678"),
		[]byte("/ip4/127.0.0.1/tcp/50234"),
		//[]byte("/ip4/127.0.0.1/udp/1234"),
	}
	circuitPrivKeys := make([]ecdsa.PrivateKey, numRelays)
	circuitPubKeys := make([]ecdsa.PublicKey, numRelays)

	privSender, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)

	for i := 0; i < numRelays; i++ {
		pub, priv := generateHopKeys()
		circuitPrivKeys[i] = *priv
		circuitPubKeys[i] = *pub
	}

	var payload [payloadSize]byte
	copy(payload[:], []byte("hello sphinx!"))

	packet, err :=
		NewPacket(privSender, circuitPubKeys, finalAddr, relayAddrs, payload)
	if err != nil {
		t.Errorf("Err packet construction: %v", err)
		return
	}

	var buf bytes.Buffer

	// creates encoder, encodes packet and write to buffer buf
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(packet)
	if err != nil {
		t.Error(err)
		return
	}

	// TODO: check size of the packet byte stream (must be fixed!)

	// creates decoder, reads bytes from buffer and populates newPacket
	dec := gob.NewDecoder(&buf)
	var newPacket Packet
	err = dec.Decode(&newPacket)
	if err != nil {
		t.Error(err)
		return
	}

	// #TODO impl equal for header? (only necessary for tests though.. ), maybe there
	// is a smarter way for doing this. also this is ugly af
	if string(newPacket.Header.RoutingInfo[:]) != string(packet.Header.RoutingInfo[:]) {
		t.Errorf("Encoded/decoded header.RoutingInfo is not correct: %v != %v",
			newPacket.Header, packet.Header)
	}

	if string(newPacket.Payload[:]) != string(packet.Payload[:]) {
		t.Errorf("Encoded/decoded packet payload is not correct: %v != %v",
			newPacket.Header, packet.Header)
	}
}

// tests the construction and processing of an onion packet with a numRelays
// size circuit.
func TestEndToEnd(t *testing.T) {
	numRelays := 5
	finalAddr := []byte("/ip6/2607:f8b0:4003:c01::6a/udp/5678#000000000")
	relayAddrs := [][]byte{
		[]byte("QmQV4LdB3jDKEZxB1EGoutUYyRSt8H8oW4B6DoBLB9z6b7"),
		[]byte("/ip4/127.0.0.1/udp/1234#0000000000000000000000"),
		[]byte("QmPxawpH7ymXENBZcbKpV3NTxMc4fs37gmREn8e9C2kgNe"),
		[]byte("/ip4/120.120.0.2/tcp/1222#00000000000000000000"),
		[]byte("/ip6/2607:f8b0:4003:c01::6a/udp/5678#000000000"),
	}

	circuitPrivKeys := make([]ecdsa.PrivateKey, numRelays)
	circuitPubKeys := make([]ecdsa.PublicKey, numRelays)

	privSender, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)

	for i := 0; i < numRelays; i++ {
		pub, priv := generateHopKeys()
		circuitPrivKeys[i] = *priv
		circuitPubKeys[i] = *pub
	}

	var payload [payloadSize]byte
	copy(payload[:], []byte("hello sphinx!"))

	// initiator constructs new packet
	packet0, err :=
		NewPacket(privSender, circuitPubKeys, finalAddr, relayAddrs, payload)
	if err != nil {
		t.Errorf("Err packet construction: %v", err)
		return
	}

	// check if paylaod was encrypted
	if string(packet0.Payload[:]) == string(payload[:]) {
		t.Errorf("Payload was not successfully ENCRYPTED: %v == %v",
			packet0.Payload, payload)
	}

	// relay 0 processes the header
	r0 := NewRelayerCtx(&circuitPrivKeys[0])
	nextAddr, packet1, err := r0.ProcessPacket(packet0)
	if err != nil {
		t.Errorf("Err packet processing: %v", err)
		return
	}

	if string(packet1.Payload[:]) == string(payload[:]) {
		t.Errorf("Payload was not successfully ENCRYPTED: %v == %v",
			packet1.Payload, payload)
	}

	if string(nextAddr[:]) != string(relayAddrs[1]) {
		t.Errorf("NextAddr is incorrect (%v != %v)", string(nextAddr[:]),
			string(relayAddrs[1]))
		return
	}

	if packet1.Header == nil {
		t.Errorf("Packet's header is empty, abort. (pointer: %v)", packet1.Header)
		return
	}

	// relay 1 processes the header
	r1 := NewRelayerCtx(&circuitPrivKeys[1])
	nextAddr, packet2, err := r1.ProcessPacket(packet1)
	if err != nil {
		t.Errorf("Err packet processing: %v", err)
		return
	}

	if string(packet2.Payload[:]) == string(payload[:]) {
		t.Errorf("Payload was not successfully ENCRYPTED: %v == %v",
			packet2.Payload, payload)
	}

	if string(nextAddr[:]) != string(relayAddrs[2]) {
		t.Errorf("NextAddr is incorrect (%v != %v)", nextAddr, relayAddrs[2])
		return
	}

	// relay 2 processes the header
	r2 := NewRelayerCtx(&circuitPrivKeys[2])
	nextAddr, packet3, err := r2.ProcessPacket(packet2)
	if err != nil {
		t.Errorf("Err packet processing: %v", err)
		return
	}

	// relays 3 and 4 process the header
	r3 := NewRelayerCtx(&circuitPrivKeys[3])
	_, packet4, err := r3.ProcessPacket(packet3)
	if err != nil {
		t.Errorf("Err packet processing: %v", err)
		return
	}

	r4 := NewRelayerCtx(&circuitPrivKeys[4])
	nextAddr, packet5, err := r4.ProcessPacket(packet4)
	if err != nil {
		t.Errorf("Err packet processing: %v", err)
		return
	}
	if string(nextAddr[:]) != string(finalAddr) {
		t.Errorf("NextAddr (which is the last) is incorrect (%v != %v)",
			nextAddr, finalAddr)
		return
	}

	if packet5.IsLast() != true {
		t.Errorf("Packet should be final, hmac must be all 0s, got %v", packet3.RoutingInfoMac)
	}

	if string(packet5.Payload[:]) != string(payload[:]) {
		t.Errorf("Payload was not successfully recovered by last relay: %v != %v",
			packet5.Payload, payload)
	}
}

func TestNewHeader(t *testing.T) {
	numRelays := 4
	finalAddr := []byte("QmZrXVN6xNkXYqFharGfjG6CjdE3X85werKm8AyMdqsQKS")
	relayAddrs := [][]byte{
		[]byte("/ip4/127.0.0.1/udp/1234#0000000000000000000000"),
		[]byte("QmSFXZRzh6ZdpWXXQQ2mkYtx3ns39ZPtWgQJ7sSqStiHZH"),
		[]byte("/ip6/2607:f8b0:4003:c00::6a/udp/5678#000000000"),
		[]byte("/ip4/198.162.0.2/tcp/4321#00000000000000000000"),
		//[]byte("/ip4/198.162.0.3/tcp/4321"),
	}

	circuitPrivKeys := make([]ecdsa.PrivateKey, numRelays)
	circuitPubKeys := make([]ecdsa.PublicKey, numRelays)

	privSender, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)
	//pubSender := privSender.PublicKey

	for i := 0; i < numRelays; i++ {
		pub, priv := generateHopKeys()
		circuitPrivKeys[i] = *priv
		circuitPubKeys[i] = *pub
	}

	sharedSecrets, err := generateSharedSecrets(circuitPubKeys, *privSender)

	header, err :=
		constructHeader(privSender, finalAddr, relayAddrs, sharedSecrets)
	if err != nil {
		t.Error(err)
	}

	ri := header.RoutingInfo

	// checks if there are suffixed zeros in the padding
	count := 0
	for j := len(ri) - 1; j > 0; j-- {
		if ri[j] != 0 {
			break
		}
		count = count + 1
	}

	if count > 2 {
		t.Errorf("Header is revealing number of relays. Suffixed 0s count: %v", count)
		t.Errorf("len(routingInfo): %v | len(headerMac): %v",
			len(ri), len(header.RoutingInfoMac))
	}
}

func TestGenSharedKeys(t *testing.T) {
	// setup
	curve := ec.P256()
	numRelays := 3
	circuitPubKeys := make([]ecdsa.PublicKey, numRelays)
	circuitPrivKeys := make([]ecdsa.PrivateKey, numRelays)

	privSender, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)
	pubSender := privSender.PublicKey

	for i := 0; i < numRelays; i++ {
		pub, priv := generateHopKeys()
		circuitPrivKeys[i] = *priv
		circuitPubKeys[i] = *pub
	}

	// generateSharedSecrets
	sharedKeys, err := generateSharedSecrets(circuitPubKeys, *privSender)
	if err != nil {
		t.Error(err)
	}

	//e := ec.Marshal(pubSender.Curve, pubSender.X, pubSender.Y)
	//t.Error(e, len(e), pubSender.X.BitLen(), pubSender.Y.BitLen())

	// if shared keys were properly generated, the 1st hop must be able to 1)
	// generate shared key and 2) blind group element. The 2rd hop must be able to
	// generate shared key from new blind element

	// 1) first hop derives shared key, which must be the same as sharedKeys[0]
	privKey_1 := circuitPrivKeys[0]
	sk_1 := scrypto.GenerateECDHSharedSecret(&pubSender, &privKey_1)
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
	privKey_2 := circuitPrivKeys[1]
	sk_2 := scrypto.GenerateECDHSharedSecret(newGroupElement, &privKey_2)
	if sk_2 != sharedKeys[1] {
		t.Error(fmt.Printf("Second shared key was not properly computed\n> %x\n> %x\n",
			sk_2, sharedKeys[1]))
	}
}

func TestEncodingDecodingHeader(t *testing.T) {
	pub, _ := generateHopKeys()
	str := "dummy routing info"
	ri := [routingInfoSize]byte{}
	copy(ri[:], str[:])
	header := &Header{RoutingInfo: ri, GroupElement: *pub}

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

	if string(header.RoutingInfo[:]) != string(headerAfter.RoutingInfo[:]) {
		t.Error(fmt.Printf("Original and encoded/decoded header routing info mismatch:\n >> %v \n >> %v\n",
			string(header.RoutingInfo[:]), string(headerAfter.RoutingInfo[:])))
	}

	hGe := header.GroupElement
	haGe := headerAfter.GroupElement

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

func TestPaddingGeneration(t *testing.T) {
	numRelays := 3
	circuitPubKeys := make([]ecdsa.PublicKey, numRelays)
	circuitPrivKeys := make([]ecdsa.PrivateKey, numRelays)

	privSender, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)

	for i := 0; i < numRelays; i++ {
		pub, priv := generateHopKeys()
		circuitPrivKeys[i] = *priv
		circuitPubKeys[i] = *pub
	}

	// generateSharedSecrets
	sharedKeys, err := generateSharedSecrets(circuitPubKeys, *privSender)
	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, 24)
	padding, err := generatePadding(sharedKeys, nonce)
	if err != nil {
		t.Error(err)
	}

	expPaddingLen := (numRelays - 1) * relayDataSize
	if len(padding) != expPaddingLen {
		t.Error(fmt.Printf("Final padding should have lenght of |(numRelays - 1) * relaysDataSize| (%v), got %v", expPaddingLen, len(padding)))
	}

}

// helpers
func generateHopKeys() (*ecdsa.PublicKey, *ecdsa.PrivateKey) {
	privHop, _ := ecdsa.GenerateKey(ec.P256(), rand.Reader)
	pubHop := privHop.Public().(*ecdsa.PublicKey)
	return pubHop, privHop
}
