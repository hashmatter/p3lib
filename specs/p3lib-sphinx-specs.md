# p3lib-sphinx specifications

`p3lib-sphinx` implements the sphinx packet format as defined by [1]. The
package implements the data structures and primitives for creating, relaying and
verifying sphinx packets.

A sphinx packet encapsulates information to cryptographically secure and verify
integrity of the channel at each relay. Ephemeral keys are distributed between
the packet sender and the relays, so that relays can decode and access their 
routing information and message payload. Sphinx use Diffie-Hellman for key
distribution.

## Data structures

### A. Packet format

A sphinx packet wraps the encrypted layers for each of the relays to decrypt and
retrieve routing data necessary to forward the packet to the next relay. The
packet does not leak information about the identity of previous and next
relays and position of the relay in the path. The source node and each of the
relays perform ECDH to derive a secret key which is used to 1) verify the MAC of
the header; 2) decrypt the set of routing information needed by the relay and 3)
shuffle the ephemeral key for the next hop.

A sphinx packet contains the following fields:

`Version (byte)` version of the packet. All versions should be backwards
compatible. Current version is `1`;

`EphemeralKey (rsa.PublicKey)` used by the relays in combination with the 
private key derived in the ECDH process.

`RoutingInfo (routingData)` encodes all the routing info for the relay and hops.

`HeaderMAC ([]byte)` HMAC of the packet header.

### B. Routing data format

## API

## Constants

### References

[1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)

