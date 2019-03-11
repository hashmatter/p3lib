# p3lib specifications

p3lib is a library with primitives for privacy preserving routing and messaging 
in P2P networks.

| Layer | p3lib component |
| --- | --- |
| Packet format  | `p3lib-sphinx` [1]  |

As a general design goal, p3lib is built to seamlessly integrate with
[libp2p](https://github.com/libp2p).

## p3lib-sphinx

`p3lib-sphinx` implements the sphinx packet format as defined by [1].
[p3lib-sphinx specifications](./p3lib-sphinx-specs.md)

### References

[1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)

