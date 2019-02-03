# p3lib

![Version](https://img.shields.io/badge/version-0.1-blue.svg?style=for-the-badge)

**p3lib, the toolbox for engineers to enhance privacy in P2P networks**

p3lib implements a set of privacy preserving primitives (p3) and protocols for
routing and messaging in P2P networks. p3lib is currently focusing on
onion-based routing protocols for any type of P2P networks. It implements onion
packet formats, routing protocols and path construction strategies that can be
used to enhance network privacy. Currently, the protocols and primitives
implemented by p3lib are based on research works such as Sphinx [1], HORNET [2]
and ShwadowWalker [3]. 

| Layer | p3lib components |
| --- | --- |
| Packet format  | `p3lib-sphinx` [1]  |
| Routing  | `p3lib-hornet` [2]  |
| Path construction  | `p3lib-shadowwalker` [3]  |

For more information about each p3lib component, check the [specifications](./specs).

### Privacy design

p3lib provides a set of interfaces that play together nicely and can be used
separately or as a whole. The [interfaces](./specs/interfaces.md) specs show the
current interfaces and abstractions that p3lib exposes and implements.

p3lib is designed to integrate seamlessly with [libp2p](https://github.com/libp2p).

### References

[1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)

[2] [HORNET: High-speed Onion Routing at the Network Layer](https://dl.acm.org/citation.cfm?id=2813628)

[3] [ShadowWalker: Peer-to-peer Anonymous Communication Using Redundant Structured Topologies](https://dl.acm.org/citation.cfm?id=1653683&dl=ACM&coll=DL)

### Contributing

Fork and PR. Issues for discussion.

### License and support

© MIT (hashmatter)

This work is supported by [hashmatter](https://hashmatter.com). Want to become
a supporter? [Reach out!](mailto:mx@hashmatter.com?subject=[p3lib]%20Become%20a%20backer!)
