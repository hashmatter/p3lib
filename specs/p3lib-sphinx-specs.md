# p3lib-sphinx specifications

`p3lib-sphinx` implements the sphinx packet format as defined by [1]. This
package implements the data structures and primitives for creating, relaying and
verifying sphinx packets for onion routing and mix-networks.

## Protocol overview

## Onion packet and header

An onion packet contains the `version` of the packet, an `header` containing 
information for the relay to generate shared keys and, if that is the case, 
blinded data for next relays. It also contains `routing info` with the necessary
information to route the packet for the next relay and, finally, the HMAC of the
packet's header, used for integrity verification.

The size of the `header` must be invariant throughout the circuit so that its
position in the circuit is not leaked. The size of the `header` depends on the
max. number of relays allowed for each circuit and the size of the keys.

*Notes on defaults: current version of p3lib-sphinx (v0.1) sets sensible and
secure defaults for the ECC curve, key sizes and max. number or relays. this
will change in the future to allow more flexibility to developers to bing their
own crypto and adapt to their application needs*

### Header

An header contains a `group_element` and a `payload`. The `group_element` is  sender's
blinded public key and a `payload` is the header's payload with the information
for the next relay. 
The size of the `header` must be invariant and deterministic depending on the
cryptography defaults and it is calculated by the formula:

```
  size_header = p + (2 * r * k)     where,

 p: size of the public key (bytes)
 r: max number of hops
 k: security parameter, ie. size of symmetric key (bytes) 
```

For version `v0.1`, the size of an header is `33 + (2 * 5 * 16) = 193` bytes

### Packet

A sphinx packet wraps the encrypted layers for each of the relays to decrypt and
retrieve routing data necessary to forward the packet to the next relay. The
packet does not leak information about the identity of previous and next
relays and position of the relay in the path. The source node and each of the
relays perform ECDH to derive a secret key which is used to 1) verify the MAC of
the header; 2) decrypt the set of routing information needed by the relay and 3)
shuffle the ephemeral key for the next hop.

A packet encapsulates both the `header` and the message `payload`. Both `header`
and `payload` must be invariant in length, so that colluding relays cannot link 
packets across the circuit. A packet also contains a `version`, `routing_info`
and `header_hmac`. The size of the packet is the sum of the size of those
fields:

```
  size_packet = size_header + size_version + size_routing_info + size_payload

	 where

  size_routing_info = r * (address_size + header_hmac_size)
```

An `address` contains an IPv4 or IPv6 address (16 bytes) and an unique ID for
the communication protocol (1 byte). The `header_hmac` is the HMAC of each of
the headers computed by the hash function `SHA256-MAC-128`.

For version `v0.1`, the size of the routing info is `5 * (17 + 32) = 245` bytes.
A packet payload has a fixed lenght of 256 bytes.

A sphinx packet is  `193 + 1 + 245 + 256 = 695` bytes long. This means that for
each 256 bytes transmitted, there is an overhead of 450 bytes.

**API**

1) Create and encode packet

``` go
// creates a new packet
packet, _ := 
	NewPacket(sessionKey, circuitPubKeys, finalAddr, relaysAddrs, payload)

// encodes packet and writes it to a network buffer to be sent over the wire 
// to the next relay
var network bytes.Buffer
enc := gob.NewEncoder(&network)
_ = enc.Encode(packet)
```

2) Receive, decode and process packet

``` go
// initiates the relay context used to process the packet
ctx := NewRelayerCtx(privKey)

// decodes bytes from network into packet
dec := gob.NewDecoder(&network)
var packet Packet
_ = dec.Decode(&newPacket)

// processes packet in the relayer context
nextAddr, nextPacket, _ := ctx.ProcessPacket(packet)

// checks if packet resulting from the packet processing is last
if isLast := nextPacket.IsLast(); isLast == true {
	
	// if packet is last, forward payload to destination
	forwardToDestination(nextAddr, nextPacket)
	return
}

// if packet is not last, forward it to next relay
forwardToRelay(nextAddr, nextPacket)
```

3) Check relay context state

``` go
ctx := NewRelayerCtx(privKey)

// ...

// gets all the tags of the processed packets
tags := ctx.ListProcessedPackets()
```

## Cryptography

Different hash functions are used to generate encryption and verification keys
of the Sphinx and integrity verification. 

### Key Generation 

- `encryption`: string which converted to byte stream is used as key for data 
obfuscation at each hop.

- `hash`: string which converted to byte stream is used as key for calculating
header and payload MAC

The default hash function used in the current version is `SHA256-MAC-128`. In
the future, the developer may use other sensible hash functions.

### PRG obfuscation

A secure pseudo-random stream is used to obfuscate the payload of the packet at
each hop, so that relayers can only access the routing information necessary for
forwarding the packet to the next hop. The default PR byte stream used to
encrypt the packet is `ChaCha20` initialized with a `0x00` byte stream and the
hop's shared secret. (Security note: it is secure to use a fixed nonce since the
shared key is never reused).

### References

- [1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)
