# Coin Flipping Request Delegation

The goal of Coin Flipping Request Delegation (CFRD) is to add plausible
deniability of routing and lookup requests in P2P networks, with special
emphasis on DHT networks. The CFRD lookup protocol works by probabilistically
creating a new lookup from a received routing request in order to add noise
(potentially useful) noise against passive local adversaries.

###  Example: CFRD in Kademlia DHT

In a Kademlia lookup request (as defined by these specs), the lookup initiator
creates an ordered shortlist containing k peers closest to the ID of the
contentID requested. The shortlist is ordered by proximity and is first
populated with peers in the initiator's bucket list. Each iteration of the
protocol consists of selecting α of the closest peers to the `contentID` in the
shortlist and issue in parallel a `FIND_VALUE` request to them. The responses
contain a set of the closest peers of each of the peers which that received the
`FIND_VALUE` request. This information is added to the shortlist in a way that it
maintains its order (i.e. first peers are closer to the `contentID`). This
protocol proceeds until 1) a peer responds with STORE message (value found); 2)
an iteration in which no new peer is added to the shortlist (value not found)
and; 3) lookup timeout.

The CFRD construction transforms `FIND_VALUE` requests into new `FIND_VALUE`
requests in a probabilistic way. When a peer receives a `FIND_VALUE` request, it
will flip a coin to decide whether to respond to the request or instead start a
lookup request itself. Once the lookup is resolved by the new peer (which is not
the original initiator), it will cache the content and reply to the peer which
initially asked for the content with a STORE message.

This mechanism adds plausible deniability to DHT lookups, since (privacy)
adversaries monitoring network requests (locally and to a certain threshold)
will not be able to distinguish between original content lookups from lookups
that were initiated because of the CFRD mechanism. This mechanism aims at
decoupling peer behaviour (network request) from user behaviour (interests and
personal behaviour).
