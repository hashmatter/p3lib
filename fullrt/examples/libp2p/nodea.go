package main

import (
	"context"
	"github.com/hashmatter/p3lib/fullrt"
	host "github.com/libp2p/go-libp2p-host"
	"log"
)

var protocolID = "/p3lib/fullrt/1.0"

// nodeb has a fixed identity and should be listening to localhost:4002
var nodeb = "/ip4/127.0.0.1/tcp/4002/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"

func main() {
	ctx := context.Background()
	host, err := libp2p.New(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// connects to nodeb
	nodebAddr, _ := ipfsaddr.ParseString(nodeb)
	peerinfo, _ := pstore.InfoFromP2pAddr(nodebAddr.Multiaddr())

	if err = host.Connect(ctx, *peerinfo); err != nil {
		log.Println("ERROR: ", err)
	}
}
