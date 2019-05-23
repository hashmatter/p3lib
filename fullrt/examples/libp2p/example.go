// This example spins up two libp2p hosts that exchange full routing table
// with the protocol defined by p3lib-fullrt. `nodeA` is responsible to connect
// to nodeB - which has a fixed identity and accepting connections to a well
// defined port - and request its full routing table by intiating an exchange
// protocol with ID `/p3lib/fullrt/1.0`. `nodeB` handles the protocol request
// and uses the p3lib-fullrt helpers to parse and encode its current routing
// table.
package main

import (
	"context"
	frt "github.com/hashmatter/p3lib/fullrt"
	ipfsaddr "github.com/ipfs/go-ipfs-addr"
	libp2p "github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p-crypto"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	inet "github.com/libp2p/go-libp2p-net"
	peer "github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	proto "github.com/libp2p/go-libp2p-protocol"
	"log"
	"os"
	"time"
)

var protocolID = proto.ID("/p3lib/fullrt/1.0")
var nodebConnAddr = "/ip4/127.0.0.1/tcp/4002"
var nodebID = "QmcJzkupSVnePbJWBFU6YXq5Gk59m8cyY8KwFN57cMcAix"

func main() {
	go func() {
		startNodeB()
	}()

	go func() {
		startNodeA()
	}()

	select {}
}

// starts nodeA that will connect to nodeB and request its full routing table
func startNodeA() {

	log.Println("**NodeA** | waits 20s to let nodeb init")
	time.Sleep(time.Second * 20)

	log.Println("**NodeA** | init")

	ctx := context.Background()
	host, err := libp2p.New(ctx)
	if err != nil {
		log.Fatal(err)
	}

	nodebAddr, _ := ipfsaddr.ParseString(nodebConnAddr + "/ipfs/" + nodebID)
	peerinfo, _ := pstore.InfoFromP2pAddr(nodebAddr.Multiaddr())

	if err = host.Connect(ctx, *peerinfo); err != nil {
		log.Println("**NodeA** | ERROR: ", err)
	}

	peeridb, err := peer.IDB58Decode(nodebID)
	if err != nil {
		log.Fatal(err)
	}

	stream, err := host.NewStream(context.Background(), peeridb, protocolID)
	if err != nil {
		log.Fatal(err)
	}

	_, err = stream.Write([]byte{})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("**NodeA** | fullRT request sent")
}

func startNodeB() {
	log.Println("==NodeB== | init")
	ctx := context.Background()

	// reloads node identity from file, so that nodeA can find nodeB without any
	// discovery mechanism
	priv, err := reloadIdentityFromFile()
	if err != nil {
		log.Fatal(err)
	}

	// creates libp2p host with ID `QmcJzkupSVnePbJWBFU6YXq5Gk59m8cyY8KwFN57cMcAix`
	// listening to incoming requests at `/ip4/127.0.0.1/tcp/4002`
	host, err := libp2p.New(ctx,
		libp2p.ListenAddrStrings(nodebConnAddr),
		libp2p.Identity(priv),
	)

	// joins the IPFS DHT in order to populate routing table
	log.Println("==NodeB== | joining IPFS dht")
	kad, err := dht.New(ctx, host)
	if err != nil {
		panic(err)
	}

	for _, peerAddr := range bootstrapPeers {
		pAddr, _ := ipfsaddr.ParseString(peerAddr)
		peerinfo, _ := pstore.InfoFromP2pAddr(pAddr.Multiaddr())

		if err = host.Connect(ctx, *peerinfo); err != nil {
			log.Println("ERROR: ", err)
		}
	}

	log.Println("==NodeB== | OK host id:", host.ID())
	if err != nil {
		log.Fatal(err)
	}

	// #TODO: initiates fullRT provider
	fullRtProv := frt.NewRTProvider(kad.RoutingTable())

	// sets the handler to reply for full routing table requests
	host.SetStreamHandler(protocolID, func(stream inet.Stream) {
		log.Println("==NodeB== | received new stream: ", stream)

		defer stream.Close()

		// fetches and encodes full routing table
		err, rtBytes := fullRtProv.GetFullRoutingTable()
		if err != nil {
			log.Fatal(err)
		}

		// writes results to stream
		_, err = stream.Write(rtBytes)
		if err != nil {
			log.Fatal(err)
		}
	})
}

func reloadIdentityFromFile() (crypto.PrivKey, error) {
	var emptyPk crypto.PrivKey
	privRaw := make([]byte, 1196)
	f, err := os.Open("priv.byte")
	if err != nil {
		return emptyPk, err
	}
	defer f.Close()
	_, err = f.Read(privRaw)
	if err != nil {
		return emptyPk, err
	}
	priv, err := crypto.UnmarshalPrivateKey(privRaw)
	if err != nil {
		return emptyPk, err
	}
	return priv, nil
}

// bootstrapPeers to join the IPFS DHT
var bootstrapPeers = []string{
	"/ip4/104.131.131.82/tcp/4001/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	"/ip4/104.236.179.241/tcp/4001/ipfs/QmSoLPppuBtQSGwKDZT2M73ULpjvfd3aZ6ha4oFGL1KrGM",
	"/ip4/104.236.76.40/tcp/4001/ipfs/QmSoLV4Bbm51jM9C4gDYZQ9Cy3U6aXMJDAbzgu2fzaDs64",
	"/ip4/128.199.219.111/tcp/4001/ipfs/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu",
	"/ip4/178.62.158.247/tcp/4001/ipfs/QmSoLer265NRgSp2LA3dPaeykiS1J6DifTC88f5uVQKNAd",
}
