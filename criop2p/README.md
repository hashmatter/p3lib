## Content Resolver with Interest Obfuscation in P2P networks (CRIOP2P)

An obfuscation scheduler is an algorithm that schedules content replication in
P2P networks so that:

1) scheduler resolves location of a resource in the network; (while)
2) peers can strongly deny they have used/are interested in a resource requested
and cached (i.e. peers do not leak behaviour`*` information)
3) requests are latency sensitive (i.e. the scheduler gives priority to peers
which are closer and thus with smaller communication latency)

`*` behaviour is defined as what network content a peer requests from other
peers based on its preferences  
