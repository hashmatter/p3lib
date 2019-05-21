# p3lib specifications

p3lib is a library with primitives for privacy preserving routing and messaging 
in P2P networks.

| Layer | p3lib component |
| --- | --- |
| Packet format  | `p3lib-sphinx` [1]  |
| Octopus lookup | `p3lib-multipathlookup`, `p3lib-shadownode` [2] |

As a general design goal, p3lib is built to seamlessly integrate with
[libp2p](https://github.com/libp2p).

## p3lib-sphinx

`p3lib-sphinx` implements the sphinx packet format as defined by [1].
[p3lib-sphinx specifications](./p3lib-sphinx.md)

## p3lib-octopusdht

`p3lib-octopusdht` implements a set of primitives necessary to construct and
reply to Octopus DHT lookup [2] requests

### References

[1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)

[2] [Octopus: A Secure and Anonymous DHT Lookup](https://ieeexplore.ieee.org/document/6258005)
