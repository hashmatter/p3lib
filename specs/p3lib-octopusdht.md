# p3lib-octopusdht

`p3lib-octopusdht` implements the primitives necessary to use Octopus DHT lookup
 [1] protocol in Kademlia DHT. Octopus DHT lookup defines how to 

	1) detect and flag active adversaries that modify their routing tables to 
increase their success on passive attacks and 

	2) the lookup protocol that decreases significantly the chances of linking
DHT lookup initiator with a lookup request.

The assumptions for achieving anonymous lookup are that an adversary controls up
 to 20% of the nodes in the network and that there are no active adversaries in
the network (since they are removed and have few incentives to try the attack).

## Components

`p3lib-octopusdht` defines a set of primitives that can be used individually or
wired up together to run the Octopus DHT lookup. It is a goal of this 
implementation to be fully compatible with [libp2p](https://github.com/libp2p/go-libp2p).

### Interface

```go
import (
	kb "github.com/libp2p/go-libp2p-kbucket"
)

type OctopusManager interface {
	// Lookup exposes a 
	Lookup(string, kb.RoutingTable, context.Context) (error, <-chan pstore.PeerInfo)
}
```

### Primitives against Passive Attacks

**A. Requesting full routing table**

One of the main ideas behind the protocol is that lookup initiators request for
the full routing table of its peers, instead of a `GET_VALUE` request with the
specific resource ID of the query. Although vulnerable to range estimation
attacks [1], this technique helps to obfuscate the initiator's request and it is
part of the overall lookup protocol.

	- `requestFullRoutingTable(protocolId, peerId, IpfsDHT, opts)`: dials the peerId host
	  requesting its full routing table using `protocolId` and a set of options.

	- `handleFullRoutingTableReq(inet.Stream, IpfsDHT, opts)`: handler for 
		full routing table requests. Options may define compression techiques.

**B. Create Multipath**

Creates the set of lookup paths for constructing the multipath lookup

**C. Creating noise requests**

Noise requests are dummy requests that are used to decrease the chances of
adversaries to perform range estimation attacks

### Primitives against Active Attacks

*WIP*

[1] Wang, Qiyan & Borisov, Nikita. (2012). Octopus: A secure and anonymous DHT
lookup. Proceedings - International Conference on Distributed Computing Systems.
10.1109/ICDCS.2012.78.
