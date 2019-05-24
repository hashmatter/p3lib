## fullrt - Protocol for full routing table exchange

`p3lib-fullrt` defines and implements a protocol for peers in P2P networks to
request and provide information about their routing table. This mechanism can be
used as a building block to construct protocols for privacy preserving lookups
in P2P networks such as DHTs. It can also be used as a way for peers to exchange
routing information for metrics, security checks [1]  and performance optimizations.

### p3lib-fullrt as a privacy enhancing mechanism for DHT lookups

`p3lib-fullrt` has been designed primarily as a mechanism for enhancing privacy
on DHT lookups. In many vanilla DHT designs (e.g. Kademlia DHT [2]), the lookup
initiator recursively requests other peers for a subset of their routing table
containing the peers closest to a certain ID - the resource/peer ID the lookup
initiator is interest. This protocol, although effective and highly scalable -
leaks information of the lookup initiator's interests to other network peers.

In order to not leak the lookup initiator's interest, she can request the full
routing table from other peers and select the subset closest to her interest
locally. Note that this approach, although much better from a privacy
perspective than vanilla Kademlia - is still vulnerable to passive Range Estimation
attacks [1] and active Lookup Bias attacks [1]. These vulnerabilities can be
addressed by other primitives and protocols implemented by `p3lib`.

### API

```go
// instantiates a routing table 
rt := kb.NewRoutingTable(10, peerID, time.Duration(time.Second*1), pstore.NewMetrics())

// starts a full routing table provider with a pointer to a routing table
fullRTManager := NewRTProvider(rt)
err, rtBytes := fullRTManager.GetFullRoutingTable()

// rtBytes is an encoded and compressed (optional) snapshot of the current
// routing table which can sent to other network peers

// parse routing table
fullrt := RoutingTableRaw{}
json.Unmarshal(res, &rtBytes)

// for libp2p routing tables, print peer IDs of the routing table
for _, r := range fullrt {
 log.Println(peer.IDB58Decode(r))
}
```

Check the [libp2p example](./examples/libp2p) to see how to define the full
blown protocol to exchange full routing table information between two network 
peers.

### Examples

Check the [example directory](./examples/) to see how to use `p3lib-fullrt` with
[libp2p](https://github.com/libp2p/go-libp2p).

### FAQ

**1. Is using p3lib-fullrt enough to ensure that the lookup initiator's
interest not disclosed to other peers?**

Not entirely. This approach, although much better from a privacy
perspective than vanilla Kademlia - is still vulnerable to passive Range Estimation
attacks [1] and active Lookup Bias attacks [1]. These vulnerabilities can be
addressed by other primitives and protocols implemented by `p3lib`. However, it
does make it harder for attackers to infer the lookup initiator objectives and
it requires more resources (i.e. more colluding peers) to effectively perform 
the attack.

Keep in mind that `p3lib-fullrt` is one piece of the puzzle for providing
privacy for DHT lookup initiators.

**2. Why isn't requesting the full routing table part of the DHT protocol
implementations?**

Because in most cases, that is not how the lookup protocol is defined. It is
much more resource efficient for peers to exchange a subset of entries of the
routing table since it requires less data in the wire. But privacy requires most
often than not more overhead and resource consumption. Having `p3lib-fullrt` as
an optional mechanism to use allows developers to selectively pick which lookups
are important to maintain as private as possible, while leaving other lookups to
be more efficient and less private. We aim at building **plug and play privacy**
and giving as much flexibility as possible to dweb app developers and
requirements.

**3. Peers are exchanging a full routing table over the wire. Isn't this too
expensive?**

It could be. We are planning to implement compression and sampling in
`p3lib-fullrt`. The goal is to make it optional for peers to request the full
routing table or a sample of it (e.g. 40% of its entries, as distributed through
the network topology as possible).

### References

[1] [Octopus: A Secure and Anonymous DHT Lookup](https://ieeexplore.ieee.org/document/6258005)

[2] [Kademlia DHT](https://en.wikipedia.org/wiki/Kademlia)
