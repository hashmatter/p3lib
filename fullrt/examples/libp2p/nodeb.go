package main

import (
	"context"
	"github.com/hashmatter/p3lib/fullrt"
	host "github.com/libp2p/go-libp2p-host"
	"log"
)

var protocolID = "/p3lib/fullrt/1.0"

func main() {
	ctx := context.Background()

	// #TODO: create node with fixed identity
	// #TODO: listens to localhost:4002 instead of default
	host, err := libp2p.New(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// #TODO: initiates fullRT provider

	// #TODO: joins the IPFS DHT in order to populate routing table

	// sets the handler to reply for full routing table requests
	host.SetStreamHandler(protoDiscovery, func(stream inet.Stream) {

		// fetches and encodes full routing table

		// writes results to stream
		_, err := stream.Write(encrt)
		if err != nil {
			log.Fatal(err)
		}
		stream.Close()
	})
}
