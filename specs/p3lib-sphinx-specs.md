# p3lib-sphinx specifications

`p3lib-sphinx` implements the sphinx packet format as defined by [1]. This
package implements the data structures and primitives for creating, relaying and
verifying sphinx packets. The first version of the package is highly inspired on
the Sphinx onion routing implementation by Lightning Network [2].

A sphinx packet encapsulates information to cryptographically secure and verify
integrity of the channel at each relay. Ephemeral keys are distributed between
the packet sender and the relays, so that relays can decode and access their 
routing information and message payload. Sphinx use Diffie-Hellman for key
distribution.

## Protocol overview

## Data structures

> To finish

### A. Packet format

A sphinx packet wraps the encrypted layers for each of the relays to decrypt and
retrieve routing data necessary to forward the packet to the next relay. The
packet does not leak information about the identity of previous and next
relays and position of the relay in the path. The source node and each of the
relays perform ECDH to derive a secret key which is used to 1) verify the MAC of
the header; 2) decrypt the set of routing information needed by the relay and 3)
shuffle the ephemeral key for the next hop.

A sphinx packet contains the following fields:

- `Version (byte)` version of the packet. All versions should be backwards
compatible. Current supported version are `[1]`.
- `EphemeralKey (crypto.PublicKey)` used by the relays in combination with the 
private key derived in the ECDH process. 
- `RoutingInfo (routingData)` encodes all the routing info for the relay and hops.
- `HeaderMAC ([]uint8)` HMAC of the packet header.

## Cryptography

Different hash functions are used to generate encryption and verification keys
of the Sphinx and integrity verification. 

### Key Generation 

- `rho`: key generation to be used by the PRG for data obfuscation at each hop.
  Default hash function: `SHA256-MAC-128`;
- `mu`: key generation for HMAC (Default hash function: `SHA256-MAC-128`);

### PRG obfuscation

A secure pseudo-random stream is used to obfuscate the payload of the packet at
each hop, so that relayers can only access the routing information necessary for
forwarding the packet to the next hop. The default PR byte stream used to
encrypt the packet is `ChaCha20` initialized with a `0x00` byte stream and the
hop's shared secret. (Security note: it is secure to use a fixed nonce since the
shared key is never reused).

## API

> to define

## Constants

> to finish

### References

- [1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)

- [2] [Lightning Network onion routing specs](https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md)

