# p3lib specifications

p3lib is a library with primitives for privacy preserving routing and messaging 
in P2P networks. It is split into 3 main components:

| Layer | p3lib component |
| --- | --- |
| Packet format  | `p3lib-sphinx` [1]  |
| Routing  | `p3lib-hornet` [2]  |
| Path construction  | `p3lib-shadowwalker` [3]  |

## p3lib-sphinx

`p3lib-sphinx` implements the sphinx packet format as defined by [1].
[p3lib-sphinx specifications](./p3lib-sphinx-specs.md)

## p3lib-hornet

`p3lib-hornet` implements the onion routing protocol as defined by [2].
[p3lib-hornet specifications](./p3lib-hornet-specs.md)

## p3lib-shadowwalker

`p3lib-shadowwalker` implements the mechanisms and primitives to select a subset
 of random peers in structured P2P networks as defined by [3].
[p3lib-shadowwalker specifications](./p3lib-shadowwalker-specs.md)

### References

[1] [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf)

[2] [HORNET: High-speed Onion Routing at the Network Layer](https://dl.acm.org/citation.cfm?id=2813628)

[3] [ShadowWalker: Peer-to-peer Anonymous Communication Using Redundant Structured Topologies](https://dl.acm.org/citation.cfm?id=1653683&dl=ACM&coll=DL)

