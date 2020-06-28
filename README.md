# p3lib

[![Build Status](https://api.travis-ci.org/hashmatter/p3lib.svg)](https://travis-ci.org/hashmatter/p3lib) ![Version](https://img.shields.io/badge/version-0.1-blue.svg)

**The toolbox for enhancing privacy in P2P networks**

p3lib implements a set of privacy preserving primitives and protocols that help
engineers to build P2P and decentralized systems that protect peer's privacy. 

The primitives implemented by p3lib are based on privacy enhancing technology
research:

- `p3lib-sphinx` implements a general-purpose onion routing packet
construction and processor based on Sphinx [1]. p3lib aims at adding more primitives and
protocols in the future. Stay tuned and [let us know what you'd like to see as part of p3lib](https://github.com/hashmatter/p3lib/issues/18)
library.

- `p3lib-fullrt` implements a full routing table DHT lookup for libp2p that was
  suggested by OctupusDHT [2], to protect DHT initiator privacy during the
recursive network lookup.

- `p3lib-sinkhole` is a computational PIR system [3] that complements DHT lookups
	and guarantees probavle privacy for DHT lookup initiators


| Layer | p3lib components | implementation status |
| --- | --- | --- |
| Packet format  | `p3lib-sphinx` [1]  | v0.1 |
| Full Routing Table request | `p3lib-fullrt` [2] | v0.1 |
| Sinkhole DHT | `p3lib-sinkhole` | specs |

If you are interested about implementation details and APIs of p3lib components,
check the [specifications](./specs).

p3lib is designed to integrate seamlessly with [libp2p](https://github.com/libp2p).

Do you have ideas about some rad stuff you'd like to see implemented by p3lib?
Open an issue or [let's have a chat](https://twitter.com/gpestana)!.

### References

[1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)

[3] [Private Information Retrieval](https://wikipedia.com/Private_information_retrieval)

### Contributing

Fork and PR. Issues for discussion.

### License and support

© MIT (hashmatter)

This work is supported by [hashmatter](https://hashmatter.com). Want to become
a supporter? [Reach out!](mailto:mx@hashmatter.com?subject=[p3lib]%20Become%20a%20backer!)
