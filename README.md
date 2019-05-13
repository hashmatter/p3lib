# p3lib

[![Build Status](https://api.travis-ci.org/hashmatter/p3lib.svg)](https://travis-ci.org/hashmatter/p3lib) ![Version](https://img.shields.io/badge/version-0.1-blue.svg)

**The toolbox for engineers to enhance privacy in P2P networks**

p3lib implements a set of privacy preserving primitives (p3) and protocols for
routing and messaging in P2P networks. It's basically plug-and-play privacy for
your decentralized and distributed systems.

The primitives implemented by p3lib are based on privacy enhancing tech
research. As an example, `p3lib-sphinx` implements a general-purpose onion routing packet
construction and processor based on Sphinx [1]. p3lib aims at adding more primitives and
protocols in the future. Stay tuned and [let us know what you'd like to see as part of p3lib](https://github.com/hashmatter/p3lib/issues/18)
library.

| Layer | p3lib components | implementation status |
| --- | --- | --- |
| Packet format  | `p3lib-sphinx` [1]  | v0.1 |
| Plausible deniability protocol | `p3lib-cfrd` | specs |
| Octopus lookup | `p3lib-multipathlookup`, `p3lib-shadownode` [2] | specs |

If you are interested about implementation details and APIs of p3lib components,
check the [specifications](./specs).

### Privacy design

p3lib provides a set of interfaces that play together nicely and can be used
separately or as a whole. The [interfaces](./specs/interfaces.md) specs show the
current interfaces and abstractions that p3lib exposes and implements.

p3lib is designed to integrate seamlessly with [libp2p](https://github.com/libp2p).

Do you have ideas about some rad stuff you'd like to see implemented by p3lib?
Open an issue or [let's have a chat](https://twitter.com/gpestana)!.

### References

[1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)

[2] [Octopus: A Secure and Anonymous DHT Lookup](https://ieeexplore.ieee.org/document/6258005)

### Contributing

Fork and PR. Issues for discussion.

### License and support

© MIT (hashmatter)

This work is supported by [hashmatter](https://hashmatter.com). Want to become
a supporter? [Reach out!](mailto:mx@hashmatter.com?subject=[p3lib]%20Become%20a%20backer!)
