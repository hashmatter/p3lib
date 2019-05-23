module ex

go 1.12

require (
	github.com/hashmatter/p3lib/fullrt v0.0.0-00010101000000-000000000000
	github.com/ipfs/go-ipfs-addr v0.0.1
	github.com/libp2p/go-libp2p v0.0.28
	github.com/libp2p/go-libp2p-crypto v0.0.2
	github.com/libp2p/go-libp2p-host v0.0.3
	github.com/libp2p/go-libp2p-kad-dht v0.0.13
	github.com/libp2p/go-libp2p-net v0.0.2
	github.com/libp2p/go-libp2p-peer v0.1.1
	github.com/libp2p/go-libp2p-peerstore v0.0.6
	github.com/libp2p/go-libp2p-protocol v0.0.1
	github.com/multiformats/go-multihash v0.0.5
)

replace github.com/hashmatter/p3lib/fullrt => ../../
